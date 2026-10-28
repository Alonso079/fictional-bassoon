# Instalador transparente del agente Rust. Ejecutar elevado en Windows.
param(
    [Parameter(Mandatory=$true)][string]$AgentExe,
    [Parameter(Mandatory=$true)][string]$TrustPath,
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [Parameter(Mandatory=$true)][string]$Tenant,
    [Parameter(Mandatory=$true)][string]$SignerCertificateSha256,
    [string]$CaCertificate
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecutar como administrador.'
}
if ($ServerUrl -notmatch '^https://[^/]+$' -or $Tenant -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw 'Servidor HTTPS o tenant inválido.' }
if ($SignerCertificateSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'SHA-256 del certificado inválido.' }
if (Get-Service -Name PuniShellAgent -ErrorAction SilentlyContinue) { throw 'El servicio ya está instalado; usar actualización firmada.' }
$source = (Resolve-Path -LiteralPath $AgentExe).Path
$signature = Get-AuthenticodeSignature -LiteralPath $source
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw 'El ejecutable carece de firma Authenticode válida.' }
$sha = [Security.Cryptography.SHA256]::Create()
try { $leaf = ([BitConverter]::ToString($sha.ComputeHash($signature.SignerCertificate.RawData))).Replace('-','').ToLowerInvariant() }
finally { $sha.Dispose() }
if ($leaf -ne $SignerCertificateSha256.ToLowerInvariant()) { throw 'El certificado editor no coincide con el pin.' }
$roots = Get-Content -LiteralPath $TrustPath -Raw | ConvertFrom-Json
foreach ($name in @('server','command','license','update')) {
    if (-not $roots.$name.key_id -or -not $roots.$name.public_key_b64) { throw "Falta raíz pública: $name" }
}
$install = Join-Path $env:ProgramFiles 'PuniShell'
$state = Join-Path $env:ProgramData 'PuniShell'
New-Item -ItemType Directory -Path $install,$state -Force | Out-Null
foreach ($dir in @($install,$state)) {
    & icacls.exe $dir '/inheritance:r' '/grant:r' 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo proteger ACL: $dir" }
}
$target = Join-Path $install 'punishell-agent.exe'
Copy-Item -LiteralPath $source -Destination $target -ErrorAction Stop
$ca = $null
if ($CaCertificate) {
    $ca = Join-Path $install 'server-ca.pem'
    Copy-Item -LiteralPath $CaCertificate -Destination $ca -ErrorAction Stop
}
$config = [ordered]@{
    server_url = $ServerUrl
    tenant_id = $Tenant
    state_dir = $state
    installed_executable = $target
    server_keys = @($roots.server)
    command_keys = @($roots.command)
    license_keys = @($roots.license)
    update_keys = @($roots.update)
    ca_certificate = $ca
    managed_services = @()
    update_channels = @('stable')
    signer_certificates = @($SignerCertificateSha256.ToLowerInvariant())
    poll_seconds = 30
}
$configPath = Join-Path $install 'agent.json'
[System.IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding($false)))
& icacls.exe $configPath '/inheritance:r' '/grant:r' 'SYSTEM:F' 'Administrators:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'No se pudo proteger agent.json.' }
$code = Read-Host 'Código de activación de un solo uso'
$code | & $target enroll --config $configPath
if ($LASTEXITCODE -ne 0) { throw 'La activación falló; no se creó el servicio.' }
& $target install-service --config $configPath
if ($LASTEXITCODE -ne 0) { throw 'El servicio no se pudo instalar.' }
Write-Host "PuniShellAgent instalado y activado. Configuración: $configPath"
