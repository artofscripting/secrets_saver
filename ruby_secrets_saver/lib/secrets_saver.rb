# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "securerandom"
require "io/console"

module SecretsSaver
  class InvalidKeyOrCorruptedDataError < StandardError
    def initialize
      super("Invalid key or corrupted data.")
    end
  end

  class SecretsSaver
    DEFAULT_FILENAME = "secrets.ep"
    PBKDF2_ITERS = 600_000
    KEY_LEN = 32
    SALT_LEN = 16
    NONCE_LEN = 12

    def self.new_file(filename = DEFAULT_FILENAME, prompt: nil)
      new(filename, db_adapter: nil, prompt: prompt)
    end

    def self.new_db(db_adapter, prompt: nil)
      new(DEFAULT_FILENAME, db_adapter: db_adapter, prompt: prompt)
    end

    def initialize(filename, db_adapter: nil, prompt: nil)
      @filename = (filename.nil? || filename.empty?) ? DEFAULT_FILENAME : filename
      @db_adapter = db_adapter
      @prompt = prompt || method(:default_prompt)
      @key = nil
      @data = nil

      unless exists?
        get_key
        @data = {}
        save
      end
    end

    def set_secret(key, value)
      ensure_loaded
      @data[key] = value
      save
    end

    def get_secret(key)
      ensure_loaded
      @data[key]
    end

    def list_secrets
      ensure_loaded
      @data.keys.sort
    end

    def clear_database
      @data = {}
      save
    end

    private

    def exists?
      if @db_adapter
        !@db_adapter.read_encrypted_row.nil?
      else
        File.file?(@filename)
      end
    end

    def get_key
      return @key if @key

      location = @db_adapter ? "database" : @filename
      @key = @prompt.call(location).to_s
    end

    def derive_key(password, salt)
      OpenSSL::PKCS5.pbkdf2_hmac(password, salt, PBKDF2_ITERS, KEY_LEN, OpenSSL::Digest::SHA256.new)
    end

    def load_raw
      if @db_adapter
        row = @db_adapter.read_encrypted_row
        raise "Secrets not found in database." if row.nil?

        row
      else
        JSON.parse(File.read(@filename, mode: "r:bom|utf-8"))
      end
    end

    def save_raw(content)
      if @db_adapter
        @db_adapter.upsert_encrypted_row(content)
      else
        File.write(@filename, JSON.generate(content))
      end
    end

    def load
      content = load_raw

      salt = Base64.strict_decode64(content.fetch("salt"))
      nonce = Base64.strict_decode64(content.fetch("nonce"))
      ciphertext_plus_tag = Base64.strict_decode64(content.fetch("ciphertext"))

      raise InvalidKeyOrCorruptedDataError if ciphertext_plus_tag.bytesize < 16

      ciphertext = ciphertext_plus_tag[0...-16]
      tag = ciphertext_plus_tag[-16, 16]

      begin
        cipher = OpenSSL::Cipher.new("aes-256-gcm")
        cipher.decrypt
        cipher.key = derive_key(get_key, salt)
        cipher.iv = nonce
        cipher.auth_tag = tag
        cipher.auth_data = ""

        plaintext = cipher.update(ciphertext) + cipher.final
        @data = JSON.parse(plaintext)
      rescue OpenSSL::Cipher::CipherError
        @key = nil
        raise InvalidKeyOrCorruptedDataError
      end
    end

    def ensure_loaded
      return if @data

      if exists?
        load
      else
        @data = {}
      end
    end

    def save
      ensure_loaded

      salt = SecureRandom.random_bytes(SALT_LEN)
      nonce = SecureRandom.random_bytes(NONCE_LEN)

      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = derive_key(get_key, salt)
      cipher.iv = nonce
      cipher.auth_data = ""

      plaintext = JSON.generate(@data)
      ciphertext = cipher.update(plaintext) + cipher.final
      tag = cipher.auth_tag

      save_raw(
        {
          "salt" => Base64.strict_encode64(salt),
          "nonce" => Base64.strict_encode64(nonce),
          "ciphertext" => Base64.strict_encode64(ciphertext + tag)
        }
      )
    end

    def default_prompt(location)
      print "Enter key for #{location}: "
      if $stdin.tty?
        $stdin.noecho(&:gets).to_s.strip.tap { puts }
      else
        $stdin.gets.to_s.strip
      end
    end
  end
end
