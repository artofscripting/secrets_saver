$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'SecretsSaver.psm1') -Force

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("secrets-saver-ps-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    $file = Join-Path $tempDir 'secrets.ep'

    if ($env:SS_MASTER_KEY) {
        Set-SSMasterKey -Password $env:SS_MASTER_KEY
    }
    else {
        $secure = Read-Host -AsSecureString -Prompt 'Enter test master key'
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            Set-SSMasterKey -Password $plain
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    Initialize-SecretsSaver -Filename $file

    Set-SecretValue -Key 'a' -Value '1'
    Set-SecretValue -Key 'b' -Value '2'

    $value = Get-SecretValue -Key 'a'
    if ($value -ne '1') {
        throw "Expected value '1' for key 'a', got '$value'"
    }

    $keys = @(Get-SecretKeys)
    if (($keys -join ',') -ne 'a,b') {
        throw "Unexpected keys output: $($keys -join ',')"
    }

    Clear-SecretsDatabase
    $keysAfterClear = @(Get-SecretKeys)
    if ($keysAfterClear.Count -ne 0) {
        throw "Expected empty key set after clear"
    }

    Write-Host 'powershell_secrets_saver tests passed'
}
finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}
