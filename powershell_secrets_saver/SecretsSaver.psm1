Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:SSFilename = "secrets.ep"
$script:SSMasterKey = $null

function Set-SSMasterKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $script:SSMasterKey = [System.Text.Encoding]::UTF8.GetBytes($Password)
}

function Clear-SSMasterKey {
    $script:SSMasterKey = $null
}

function Initialize-SecretsSaver {
    param(
        [string]$Filename = "secrets.ep"
    )

    $script:SSFilename = $Filename

    if (-not (Test-Path -LiteralPath $script:SSFilename)) {
        $null = Get-SSMasterKey
        $empty = @{}
        Save-SSPayload -Data $empty
    }
}

function Set-SecretValue {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$Value
    )

    Ensure-SSInitialized
    $data = Load-SSPayload
    $data[$Key] = $Value
    Save-SSPayload -Data $data
}

function Get-SecretValue {
    param(
        [Parameter(Mandatory = $true)][string]$Key
    )

    Ensure-SSInitialized
    $data = Load-SSPayload
    if ($data.ContainsKey($Key)) {
        return $data[$Key]
    }
    return $null
}

function Get-SecretKeys {
    Ensure-SSInitialized
    $data = Load-SSPayload
    return $data.Keys | Sort-Object
}

function Clear-SecretsDatabase {
    Ensure-SSInitialized
    Save-SSPayload -Data @{}
}

function Ensure-SSInitialized {
    if (-not (Test-Path -LiteralPath $script:SSFilename)) {
        Initialize-SecretsSaver -Filename $script:SSFilename
    }
}

function Get-SSMasterKey {
    if ($null -ne $script:SSMasterKey) {
        return $script:SSMasterKey
    }

    $secure = Read-Host -AsSecureString -Prompt ("Enter key for {0}" -f $script:SSFilename)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $script:SSMasterKey = [System.Text.Encoding]::UTF8.GetBytes($plain)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    return $script:SSMasterKey
}

function Derive-SSKey {
    param(
        [byte[]]$Password,
        [byte[]]$Salt
    )

    $kdf = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $Password,
        $Salt,
        600000,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        return $kdf.GetBytes(32)
    }
    finally {
        $kdf.Dispose()
    }
}

function Test-SSAesGcmAvailable {
    return ($null -ne [Type]::GetType("System.Security.Cryptography.AesGcm"))
}

function Get-SSPythonPath {
    if ($env:VIRTUAL_ENV) {
        $venvPy = Join-Path $env:VIRTUAL_ENV "Scripts\python.exe"
        if (Test-Path -LiteralPath $venvPy) {
            return $venvPy
        }
    }

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $repoVenvPy = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $repoVenvPy) {
        return $repoVenvPy
    }

    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    throw "Python was not found. Install Python or activate a virtual environment."
}

function Invoke-SSPythonCrypto {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string[]]$Args
    )

    $py = Get-SSPythonPath
    $helper = Join-Path $PSScriptRoot "crypto_helper.py"
    if (-not (Test-Path -LiteralPath $helper)) {
        throw "Missing crypto helper: $helper"
    }

    $result = & $py $helper $Mode @Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        if ($LASTEXITCODE -eq 2) {
            $script:SSMasterKey = $null
            throw "Invalid key or corrupted data."
        }
        throw ("Python crypto helper failed: {0}" -f ($result -join "`n"))
    }

    return ($result -join "`n")
}

function ConvertTo-SSHashtable {
    param(
        [Parameter(Mandatory = $true)]$InputObject
    )

    if ($null -eq $InputObject) {
        return @{}
    }

    if ($InputObject -is [hashtable]) {
        return $InputObject
    }

    $ht = @{}
    foreach ($prop in $InputObject.PSObject.Properties) {
        $ht[$prop.Name] = [string]$prop.Value
    }
    return $ht
}

function Load-SSRaw {
    if (-not (Test-Path -LiteralPath $script:SSFilename)) {
        throw "Secrets file not found: $script:SSFilename"
    }

    $raw = Get-Content -LiteralPath $script:SSFilename -Raw
    return $raw | ConvertFrom-Json
}

function Save-SSRaw {
    param(
        [Parameter(Mandatory = $true)]$RawObj
    )

    $json = $RawObj | ConvertTo-Json -Compress
    Set-Content -LiteralPath $script:SSFilename -Value $json -NoNewline
}

function Load-SSPayload {
    $raw = Load-SSRaw

    if (-not (Test-SSAesGcmAvailable)) {
        $passwordB64 = [Convert]::ToBase64String((Get-SSMasterKey))
        $plaintextJson = Invoke-SSPythonCrypto -Mode "decrypt" -Args @(
            $passwordB64,
            [string]$raw.salt,
            [string]$raw.nonce,
            [string]$raw.ciphertext
        )

        $obj = $plaintextJson | ConvertFrom-Json
        return (ConvertTo-SSHashtable -InputObject $obj)
    }

    $salt = [Convert]::FromBase64String($raw.salt)
    $nonce = [Convert]::FromBase64String($raw.nonce)
    $ciphertextPlusTag = [Convert]::FromBase64String($raw.ciphertext)

    if ($ciphertextPlusTag.Length -lt 16) {
        $script:SSMasterKey = $null
        throw "Invalid key or corrupted data."
    }

    $cipherLength = $ciphertextPlusTag.Length - 16
    $ciphertext = New-Object byte[] $cipherLength
    $tag = New-Object byte[] 16
    [Array]::Copy($ciphertextPlusTag, 0, $ciphertext, 0, $cipherLength)
    [Array]::Copy($ciphertextPlusTag, $cipherLength, $tag, 0, 16)

    $key = Derive-SSKey -Password (Get-SSMasterKey) -Salt $salt
    $plaintext = New-Object byte[] $cipherLength

    try {
        $aes = [System.Security.Cryptography.AesGcm]::new($key)
        try {
            $aes.Decrypt($nonce, $ciphertext, $tag, $plaintext)
        }
        finally {
            $aes.Dispose()
        }
    }
    catch {
        $script:SSMasterKey = $null
        throw "Invalid key or corrupted data."
    }

    $json = [System.Text.Encoding]::UTF8.GetString($plaintext)
    $obj = $json | ConvertFrom-Json
    return (ConvertTo-SSHashtable -InputObject $obj)
}

function Save-SSPayload {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Data
    )

    if (-not (Test-SSAesGcmAvailable)) {
        $plaintextJson = $Data | ConvertTo-Json -Compress
        $passwordB64 = [Convert]::ToBase64String((Get-SSMasterKey))
        $rawJson = Invoke-SSPythonCrypto -Mode "encrypt" -Args @(
            $passwordB64,
            $plaintextJson
        )
        $rawObj = $rawJson | ConvertFrom-Json
        Save-SSRaw -RawObj $rawObj
        return
    }

    $salt = New-Object byte[] 16
    $nonce = New-Object byte[] 12
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($salt)
        $rng.GetBytes($nonce)
    }
    finally {
        $rng.Dispose()
    }

    $key = Derive-SSKey -Password (Get-SSMasterKey) -Salt $salt
    $plaintext = [System.Text.Encoding]::UTF8.GetBytes(($Data | ConvertTo-Json -Compress))

    $ciphertext = New-Object byte[] $plaintext.Length
    $tag = New-Object byte[] 16

    $aes = [System.Security.Cryptography.AesGcm]::new($key)
    try {
        $aes.Encrypt($nonce, $plaintext, $ciphertext, $tag)
    }
    finally {
        $aes.Dispose()
    }

    $ciphertextPlusTag = New-Object byte[] ($ciphertext.Length + 16)
    [Array]::Copy($ciphertext, 0, $ciphertextPlusTag, 0, $ciphertext.Length)
    [Array]::Copy($tag, 0, $ciphertextPlusTag, $ciphertext.Length, 16)

    $raw = [ordered]@{
        salt       = [Convert]::ToBase64String($salt)
        nonce      = [Convert]::ToBase64String($nonce)
        ciphertext = [Convert]::ToBase64String($ciphertextPlusTag)
    }

    Save-SSRaw -RawObj $raw
}

Export-ModuleMember -Function @(
    "Set-SSMasterKey",
    "Clear-SSMasterKey",
    "Initialize-SecretsSaver",
    "Set-SecretValue",
    "Get-SecretValue",
    "Get-SecretKeys",
    "Clear-SecretsDatabase"
)
