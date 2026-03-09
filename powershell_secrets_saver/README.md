# powershell_secrets_saver

PowerShell-native port of `secrets_saver` for Windows shells.

## Features

- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 key derivation (`600000` iterations)
- Default file extension `.ep`
- One-time master key prompt per session
- API functions:
  - `Initialize-SecretsSaver`
  - `Set-SecretValue`
  - `Get-SecretValue`
  - `Get-SecretKeys`
  - `Clear-SecretsDatabase`

## Usage

```powershell
Import-Module .\SecretsSaver.psm1 -Force

# Prompts for the master key securely on first read/write.
Initialize-SecretsSaver -Filename "secrets.ep"
Set-SecretValue -Key "api_token" -Value "super_secret_value"
Get-SecretValue -Key "api_token"
Get-SecretKeys
```
