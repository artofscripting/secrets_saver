use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const DEFAULT_FILENAME: &str = "secrets.ep";
const PBKDF2_ITERS: u32 = 600_000;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

pub type PromptFn = fn(&str) -> Result<String, SecretsError>;

#[derive(Debug)]
pub enum SecretsError {
    Io(io::Error),
    Json(serde_json::Error),
    Base64(base64::DecodeError),
    InvalidKeyOrCorruptedData,
    Crypto(String),
    Db(String),
}

impl fmt::Display for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretsError::Io(e) => write!(f, "io error: {}", e),
            SecretsError::Json(e) => write!(f, "json error: {}", e),
            SecretsError::Base64(e) => write!(f, "base64 error: {}", e),
            SecretsError::InvalidKeyOrCorruptedData => {
                write!(f, "invalid key or corrupted data")
            }
            SecretsError::Crypto(e) => write!(f, "crypto error: {}", e),
            SecretsError::Db(e) => write!(f, "db error: {}", e),
        }
    }
}

impl std::error::Error for SecretsError {}

impl From<io::Error> for SecretsError {
    fn from(value: io::Error) -> Self {
        SecretsError::Io(value)
    }
}

impl From<serde_json::Error> for SecretsError {
    fn from(value: serde_json::Error) -> Self {
        SecretsError::Json(value)
    }
}

impl From<base64::DecodeError> for SecretsError {
    fn from(value: base64::DecodeError) -> Self {
        SecretsError::Base64(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawContent {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub trait DatabaseAdapter {
    fn read_encrypted_row(&self) -> Result<Option<RawContent>, SecretsError>;
    fn upsert_encrypted_row(&self, content: &RawContent) -> Result<(), SecretsError>;
}

pub struct SecretsSaver {
    filename: PathBuf,
    db_adapter: Option<Box<dyn DatabaseAdapter>>,
    prompt: PromptFn,
    key: Option<Vec<u8>>,
    data: Option<HashMap<String, String>>,
}

impl SecretsSaver {
    pub fn new_file<P: AsRef<Path>>(filename: P) -> Result<Self, SecretsError> {
        Self::new_file_with_prompt(filename, default_prompt)
    }

    pub fn new_file_with_prompt<P: AsRef<Path>>(
        filename: P,
        prompt: PromptFn,
    ) -> Result<Self, SecretsError> {
        let mut saver = SecretsSaver {
            filename: filename.as_ref().to_path_buf(),
            db_adapter: None,
            prompt,
            key: None,
            data: None,
        };

        saver.initialize_if_missing()?;
        Ok(saver)
    }

    pub fn new_db(adapter: Box<dyn DatabaseAdapter>) -> Result<Self, SecretsError> {
        Self::new_db_with_prompt(adapter, default_prompt)
    }

    pub fn new_db_with_prompt(
        adapter: Box<dyn DatabaseAdapter>,
        prompt: PromptFn,
    ) -> Result<Self, SecretsError> {
        let mut saver = SecretsSaver {
            filename: PathBuf::from(DEFAULT_FILENAME),
            db_adapter: Some(adapter),
            prompt,
            key: None,
            data: None,
        };

        saver.initialize_if_missing()?;
        Ok(saver)
    }

    pub fn set_secret(&mut self, key: &str, value: &str) -> Result<(), SecretsError> {
        self.ensure_loaded()?;
        if let Some(data) = self.data.as_mut() {
            data.insert(key.to_string(), value.to_string());
        }
        self.save()
    }

    pub fn get_secret(&mut self, key: &str) -> Result<Option<String>, SecretsError> {
        self.ensure_loaded()?;
        Ok(self.data.as_ref().and_then(|d| d.get(key).cloned()))
    }

    pub fn list_secrets(&mut self) -> Result<Vec<String>, SecretsError> {
        self.ensure_loaded()?;
        let mut keys: Vec<String> = self
            .data
            .as_ref()
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default();
        keys.sort();
        Ok(keys)
    }

    pub fn clear_database(&mut self) -> Result<(), SecretsError> {
        self.data = Some(HashMap::new());
        self.save()
    }

    fn initialize_if_missing(&mut self) -> Result<(), SecretsError> {
        if !self.exists()? {
            self.get_key()?;
            self.data = Some(HashMap::new());
            self.save()?;
        }
        Ok(())
    }

    fn exists(&self) -> Result<bool, SecretsError> {
        if let Some(adapter) = &self.db_adapter {
            Ok(adapter.read_encrypted_row()?.is_some())
        } else {
            Ok(self.filename.exists())
        }
    }

    fn get_key(&mut self) -> Result<&[u8], SecretsError> {
        if self.key.is_none() {
            let location = if self.db_adapter.is_some() {
                "database".to_string()
            } else {
                self.filename.display().to_string()
            };
            let password = (self.prompt)(&location)?;
            self.key = Some(password.into_bytes());
        }
        Ok(self.key.as_deref().unwrap_or_default())
    }

    fn derive_key(&self, password: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
        let mut out = [0u8; KEY_LEN];
        pbkdf2_hmac::<Sha256>(password, salt, PBKDF2_ITERS, &mut out);
        out
    }

    fn load_raw(&self) -> Result<RawContent, SecretsError> {
        if let Some(adapter) = &self.db_adapter {
            return adapter
                .read_encrypted_row()?
                .ok_or_else(|| SecretsError::Db("secrets not found in database".to_string()));
        }

        let raw = fs::read_to_string(&self.filename)?;
        let content: RawContent = serde_json::from_str(&raw)?;
        Ok(content)
    }

    fn save_raw(&self, content: &RawContent) -> Result<(), SecretsError> {
        if let Some(adapter) = &self.db_adapter {
            return adapter.upsert_encrypted_row(content);
        }

        let serialized = serde_json::to_string(content)?;
        fs::write(&self.filename, serialized)?;
        Ok(())
    }

    fn load(&mut self) -> Result<(), SecretsError> {
        let content = self.load_raw()?;

        let salt = STANDARD.decode(content.salt)?;
        let nonce = STANDARD.decode(content.nonce)?;
        let ciphertext = STANDARD.decode(content.ciphertext)?;

        let pass = self.get_key()?.to_vec();
        let key = self.derive_key(&pass, &salt);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| SecretsError::Crypto(format!("cipher init failed: {}", e)))?;

        let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref());
        let plaintext = match plaintext {
            Ok(v) => v,
            Err(_) => {
                self.key = None;
                return Err(SecretsError::InvalidKeyOrCorruptedData);
            }
        };

        let parsed: HashMap<String, String> = serde_json::from_slice(&plaintext)?;
        self.data = Some(parsed);
        Ok(())
    }

    fn ensure_loaded(&mut self) -> Result<(), SecretsError> {
        if self.data.is_some() {
            return Ok(());
        }

        if self.exists()? {
            self.load()?;
        } else {
            self.data = Some(HashMap::new());
        }

        Ok(())
    }

    fn save(&mut self) -> Result<(), SecretsError> {
        self.ensure_loaded()?;

        let pass = self.get_key()?.to_vec();
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);

        let key = self.derive_key(&pass, &salt);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| SecretsError::Crypto(format!("cipher init failed: {}", e)))?;

        let payload = serde_json::to_vec(self.data.as_ref().unwrap_or(&HashMap::new()))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), payload.as_ref())
            .map_err(|e| SecretsError::Crypto(format!("encrypt failed: {}", e)))?;

        let content = RawContent {
            salt: STANDARD.encode(salt),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        };

        self.save_raw(&content)
    }
}

pub fn default_prompt(location: &str) -> Result<String, SecretsError> {
    use std::io::Write;

    print!("Enter key for {}: ", location);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;
    use tempfile::tempdir;

    fn prompt_fixed(pass: String) -> PromptFn {
        if pass.ends_with("-wrong") {
            wrong_pass_prompt
        } else {
            pass_1_prompt
        }
    }

    fn test_passwords() -> (String, String) {
        let base = format!("test-{}", random::<u64>());
        (base.clone(), format!("{}-wrong", base))
    }

    fn pass_1_prompt(_: &str) -> Result<String, SecretsError> {
        Ok(PASS_1.with(|p| p.borrow().clone()))
    }

    fn wrong_pass_prompt(_: &str) -> Result<String, SecretsError> {
        Ok(WRONG_PASS.with(|p| p.borrow().clone()))
    }

    thread_local! {
        static PASS_1: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
        static WRONG_PASS: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
    }

    #[test]
    fn set_get_list_clear_file_backend() {
        let dir = tempdir().expect("temp dir");
        let file = dir.path().join("secrets.ep");
        let (good_pass, bad_pass) = test_passwords();
        PASS_1.with(|p| *p.borrow_mut() = good_pass.clone());
        WRONG_PASS.with(|p| *p.borrow_mut() = bad_pass.clone());

        let mut saver = SecretsSaver::new_file_with_prompt(&file, prompt_fixed(good_pass))
            .expect("create saver");

        saver.set_secret("a", "1").expect("set a");
        saver.set_secret("b", "2").expect("set b");

        let value = saver.get_secret("a").expect("get a");
        assert_eq!(value.as_deref(), Some("1"));

        let keys = saver.list_secrets().expect("list keys");
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);

        saver.clear_database().expect("clear db");
        assert_eq!(saver.list_secrets().expect("list after clear").len(), 0);
    }

    #[test]
    fn invalid_key_returns_expected_error() {
        let dir = tempdir().expect("temp dir");
        let file = dir.path().join("secrets.ep");
        let (good_pass, bad_pass) = test_passwords();
        PASS_1.with(|p| *p.borrow_mut() = good_pass.clone());
        WRONG_PASS.with(|p| *p.borrow_mut() = bad_pass.clone());

        let mut writer = SecretsSaver::new_file_with_prompt(&file, pass_1_prompt).expect("writer");
        writer.set_secret("x", "y").expect("writer set");

        let mut reader = SecretsSaver::new_file_with_prompt(&file, wrong_pass_prompt).expect("reader");
        let err = reader.get_secret("x").expect_err("expected invalid key");

        match err {
            SecretsError::InvalidKeyOrCorruptedData => {}
            _ => panic!("unexpected error variant"),
        }
    }
}

