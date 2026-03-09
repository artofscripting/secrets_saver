package secretssaver

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	defaultFilename = "secrets.ep"
	tableName       = "encrypted_secrets"
	keyLen          = 32
	saltLen         = 16
	nonceLen        = 12
	pbkdf2Iters     = 600000
)

var ErrInvalidKeyOrCorruptedData = errors.New("invalid key or corrupted data")

type rawContent struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type PromptFunc func(location string) (string, error)

type SecretsSaver struct {
	filename string
	db       *sql.DB
	dialect  string

	key      []byte
	data     map[string]string
	loaded   bool

	prompt PromptFunc
	mu     sync.Mutex
}

func New(filename string, db *sql.DB, prompt PromptFunc) (*SecretsSaver, error) {
	return newWithDialect(filename, db, prompt, "question")
}

func newWithDialect(filename string, db *sql.DB, prompt PromptFunc, dialect string) (*SecretsSaver, error) {
	if filename == "" {
		filename = defaultFilename
	}
	if prompt == nil {
		prompt = PromptPassword
	}

	s := &SecretsSaver{filename: filename, db: db, prompt: prompt, dialect: normalizeDialect(dialect)}

	if s.db != nil {
		if err := s.ensureSchema(); err != nil {
			return nil, err
		}
	}

	exists, err := s.exists()
	if err != nil {
		return nil, err
	}

	if !exists {
		if _, err := s.getKey(); err != nil {
			return nil, err
		}
		s.data = map[string]string{}
		s.loaded = true
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func NewFile(filename string) (*SecretsSaver, error) {
	return New(filename, nil, nil)
}

func NewDB(db *sql.DB, dialect string) (*SecretsSaver, error) {
	return newWithDialect(defaultFilename, db, nil, dialect)
}

func NewDBFromDSN(driverName, dsn, dialect string) (*SecretsSaver, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}

	s, err := newWithDialect(defaultFilename, db, nil, dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func PromptPassword(location string) (string, error) {
	if location == "" {
		location = defaultFilename
	}
	fmt.Fprintf(os.Stdout, "Enter key for %s: ", location)
	if term.IsTerminal(int(syscall.Stdin)) {
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stdout)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}

	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (s *SecretsSaver) SetSecret(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureLoadedLocked(); err != nil {
		return err
	}

	s.data[key] = value
	return s.saveLocked()
}

func (s *SecretsSaver) GetSecret(key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureLoadedLocked(); err != nil {
		return "", false, err
	}

	v, ok := s.data[key]
	return v, ok, nil
}

func (s *SecretsSaver) ListSecrets() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureLoadedLocked(); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *SecretsSaver) ClearDatabase() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data = map[string]string{}
	s.loaded = true
	return s.saveLocked()
}

func (s *SecretsSaver) ensureSchema() error {
	query := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	id INTEGER PRIMARY KEY,
	salt TEXT,
	nonce TEXT,
	ciphertext TEXT
)`, tableName)
	_, err := s.db.Exec(query)
	return err
}

func (s *SecretsSaver) exists() (bool, error) {
	if s.db != nil {
		query := fmt.Sprintf("SELECT id FROM %s WHERE id = 1", tableName)
		row := s.db.QueryRow(query)
		var id int
		err := row.Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}

	_, err := os.Stat(s.filename)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (s *SecretsSaver) getKey() ([]byte, error) {
	if len(s.key) > 0 {
		return s.key, nil
	}

	location := s.filename
	if s.db != nil {
		location = "database"
	}

	p, err := s.prompt(location)
	if err != nil {
		return nil, err
	}
	s.key = []byte(p)
	return s.key, nil
}

func (s *SecretsSaver) ensureLoadedLocked() error {
	if s.loaded {
		return nil
	}

	exists, err := s.exists()
	if err != nil {
		return err
	}
	if !exists {
		s.data = map[string]string{}
		s.loaded = true
		return nil
	}

	return s.loadLocked()
}

func (s *SecretsSaver) loadLocked() error {
	rc, err := s.loadRaw()
	if err != nil {
		return err
	}

	salt, err := base64.StdEncoding.DecodeString(rc.Salt)
	if err != nil {
		return err
	}
	nonce, err := base64.StdEncoding.DecodeString(rc.Nonce)
	if err != nil {
		return err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(rc.Ciphertext)
	if err != nil {
		return err
	}

	pass, err := s.getKey()
	if err != nil {
		return err
	}
	derived := deriveKey(pass, salt)

	block, err := aes.NewCipher(derived)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		s.key = nil
		return ErrInvalidKeyOrCorruptedData
	}

	payload := map[string]string{}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return err
	}

	s.data = payload
	s.loaded = true
	return nil
}

func (s *SecretsSaver) saveLocked() error {
	pass, err := s.getKey()
	if err != nil {
		return err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	derived := deriveKey(pass, salt)

	block, err := aes.NewCipher(derived)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	return s.saveRaw(rawContent{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
}

func deriveKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, pbkdf2Iters, keyLen, sha256.New)
}

func (s *SecretsSaver) loadRaw() (rawContent, error) {
	if s.db != nil {
		query := fmt.Sprintf("SELECT salt, nonce, ciphertext FROM %s WHERE id = 1", tableName)
		row := s.db.QueryRow(query)
		var rc rawContent
		err := row.Scan(&rc.Salt, &rc.Nonce, &rc.Ciphertext)
		if errors.Is(err, sql.ErrNoRows) {
			return rawContent{}, os.ErrNotExist
		}
		return rc, err
	}

	b, err := os.ReadFile(s.filename)
	if err != nil {
		return rawContent{}, err
	}

	var rc rawContent
	if err := json.Unmarshal(b, &rc); err != nil {
		return rawContent{}, err
	}
	return rc, nil
}

func (s *SecretsSaver) saveRaw(rc rawContent) error {
	if s.db != nil {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()

		existsQuery := fmt.Sprintf("SELECT id FROM %s WHERE id = 1", tableName)
		row := tx.QueryRow(existsQuery)
		var id int
		err = row.Scan(&id)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		if errors.Is(err, sql.ErrNoRows) {
			insertQuery := fmt.Sprintf(
				"INSERT INTO %s (id, salt, nonce, ciphertext) VALUES (1, %s, %s, %s)",
				tableName,
				s.param(1),
				s.param(2),
				s.param(3),
			)
			if _, err := tx.Exec(insertQuery, rc.Salt, rc.Nonce, rc.Ciphertext); err != nil {
				return err
			}
		} else {
			updateQuery := fmt.Sprintf(
				"UPDATE %s SET salt = %s, nonce = %s, ciphertext = %s WHERE id = 1",
				tableName,
				s.param(1),
				s.param(2),
				s.param(3),
			)
			if _, err := tx.Exec(updateQuery, rc.Salt, rc.Nonce, rc.Ciphertext); err != nil {
				return err
			}
		}

		return tx.Commit()
	}

	b, err := json.Marshal(rc)
	if err != nil {
		return err
	}
	return os.WriteFile(s.filename, b, 0o600)
}

func normalizeDialect(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "postgres", "postgresql", "pgx":
		return "postgres"
	case "mssql", "sqlserver", "sql-server":
		return "mssql"
	default:
		return "question"
	}
}

func (s *SecretsSaver) param(i int) string {
	switch s.dialect {
	case "postgres":
		return fmt.Sprintf("$%d", i)
	case "mssql":
		return fmt.Sprintf("@p%d", i)
	default:
		return "?"
	}
}

