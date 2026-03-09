using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecretsSaver;

public sealed class SecretsSaverClient
{
    private const string DefaultFilename = "secrets.ep";
    private const int Pbkdf2Iterations = 600000;
    private const int KeyLength = 32;
    private const int SaltLength = 16;
    private const int NonceLength = 12;
    private const int TagLength = 16;

    private readonly string _filename;
    private readonly IDatabaseAdapter? _dbAdapter;
    private readonly Func<string, string> _prompt;

    private byte[]? _key;
    private Dictionary<string, string>? _data;

    private SecretsSaverClient(string filename, IDatabaseAdapter? dbAdapter, Func<string, string>? prompt)
    {
        _filename = string.IsNullOrWhiteSpace(filename) ? DefaultFilename : filename;
        _dbAdapter = dbAdapter;
        _prompt = prompt ?? DefaultPrompt;

        if (!Exists())
        {
            _ = GetKey();
            _data = new Dictionary<string, string>();
            Save();
        }
    }

    public static SecretsSaverClient NewFile(string filename = DefaultFilename, Func<string, string>? prompt = null)
    {
        return new SecretsSaverClient(filename, null, prompt);
    }

    public static SecretsSaverClient NewDatabase(IDatabaseAdapter adapter, Func<string, string>? prompt = null)
    {
        return new SecretsSaverClient(DefaultFilename, adapter, prompt);
    }

    public void SetSecret(string key, string value)
    {
        EnsureLoaded();
        _data![key] = value;
        Save();
    }

    public string? GetSecret(string key)
    {
        EnsureLoaded();
        return _data!.TryGetValue(key, out var value) ? value : null;
    }

    public IReadOnlyList<string> ListSecrets()
    {
        EnsureLoaded();
        var keys = _data!.Keys.ToList();
        keys.Sort(StringComparer.Ordinal);
        return keys;
    }

    public void ClearDatabase()
    {
        _data = new Dictionary<string, string>();
        Save();
    }

    private bool Exists()
    {
        if (_dbAdapter is not null)
        {
            return _dbAdapter.ReadEncryptedRow() is not null;
        }

        return File.Exists(_filename);
    }

    private byte[] GetKey()
    {
        if (_key is not null)
        {
            return _key;
        }

        var location = _dbAdapter is not null ? "database" : _filename;
        var password = _prompt(location);
        _key = Encoding.UTF8.GetBytes(password);
        return _key;
    }

    private static byte[] DeriveKey(byte[] password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeyLength);
    }

    private RawContent LoadRaw()
    {
        if (_dbAdapter is not null)
        {
            var row = _dbAdapter.ReadEncryptedRow();
            if (row is null)
            {
                throw new FileNotFoundException("Secrets not found in database.");
            }

            return row;
        }

        var text = File.ReadAllText(_filename, Encoding.UTF8);
        return JsonSerializer.Deserialize<RawContent>(text) ?? throw new InvalidDataException("Invalid encrypted payload format.");
    }

    private void SaveRaw(RawContent content)
    {
        if (_dbAdapter is not null)
        {
            _dbAdapter.UpsertEncryptedRow(content);
            return;
        }

        var json = JsonSerializer.Serialize(content);
        File.WriteAllText(_filename, json, Encoding.UTF8);
    }

    private void Load()
    {
        var content = LoadRaw();

        var salt = Convert.FromBase64String(content.Salt);
        var nonce = Convert.FromBase64String(content.Nonce);
        var ciphertextPlusTag = Convert.FromBase64String(content.Ciphertext);

        if (ciphertextPlusTag.Length < TagLength)
        {
            _key = null;
            throw new InvalidKeyOrCorruptedDataException();
        }

        var ciphertext = ciphertextPlusTag[..^TagLength];
        var tag = ciphertextPlusTag[^TagLength..];

        var key = DeriveKey(GetKey(), salt);
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            _data = JsonSerializer.Deserialize<Dictionary<string, string>>(plaintext) ?? new Dictionary<string, string>();
        }
        catch (CryptographicException)
        {
            _key = null;
            throw new InvalidKeyOrCorruptedDataException();
        }
    }

    private void EnsureLoaded()
    {
        if (_data is not null)
        {
            return;
        }

        if (Exists())
        {
            Load();
        }
        else
        {
            _data = new Dictionary<string, string>();
        }
    }

    private void Save()
    {
        EnsureLoaded();

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var derivedKey = DeriveKey(GetKey(), salt);

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(_data);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];

        using (var aes = new AesGcm(derivedKey, TagLength))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        var ciphertextPlusTag = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, ciphertextPlusTag, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, ciphertextPlusTag, ciphertext.Length, tag.Length);

        SaveRaw(new RawContent
        {
            Salt = Convert.ToBase64String(salt),
            Nonce = Convert.ToBase64String(nonce),
            Ciphertext = Convert.ToBase64String(ciphertextPlusTag)
        });
    }

    private static string DefaultPrompt(string location)
    {
        Console.Write($"Enter key for {location}: ");
        return Console.ReadLine() ?? string.Empty;
    }
}
