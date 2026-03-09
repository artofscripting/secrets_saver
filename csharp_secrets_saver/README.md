# SecretsSaver.CSharp

C#/.NET port of the Python `secrets_saver` library.

## Features

- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 key derivation (`600000` iterations)
- Default file extension `.ep`
- File backend built in
- Optional database backend via adapter interface
- API equivalent methods:
  - `SetSecret`
  - `GetSecret`
  - `ListSecrets`
  - `ClearDatabase`

## Build And Test

```bash
dotnet test
```

## Quick Example

```csharp
using SecretsSaver;

// Prompts for the master key on first read/write.
var saver = SecretsSaverClient.NewFile("secrets.ep");
saver.SetSecret("api_token", "super_secret_value");

var token = saver.GetSecret("api_token");
Console.WriteLine(token);
```
