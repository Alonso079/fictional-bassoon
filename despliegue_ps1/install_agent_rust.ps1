# Instalador transparente del agente Rust. Ejecutar elevado en Windows.
param(
    [Parameter(Mandatory=$true)][string]$AgentExe,
    [Parameter(Mandatory=$true)][string]$TrustPath,
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [Parameter(Mandatory=$true)][string]$Tenant,
    [Parameter(Mandatory=$true)][string]$SignerCertificateSha256,
    [string]$CaCertificate,
    [ValidateRange(60,259200)][int]$DeadManSeconds = 259200
)
$ErrorActionPreference = 'Stop'
$script:InstallLogPath = $null
$script:InstallVersion = '0.0.0'
function Write-InstallEvent([string]$Event, [string]$Level = 'info') {
    if (-not $script:InstallLogPath) { return }
    try {
        if ((Test-Path -LiteralPath $script:InstallLogPath) -and (Get-Item -LiteralPath $script:InstallLogPath).Length -gt (1MB - 2048)) {
            Move-Item -LiteralPath $script:InstallLogPath -Destination ($script:InstallLogPath -replace 'installer.jsonl$','installer.1.jsonl') -Force
        }
        $record = [ordered]@{ at = [DateTime]::UtcNow.ToString('o'); level = $Level; event = $Event; version = $script:InstallVersion }
        [IO.File]::AppendAllText($script:InstallLogPath, (($record | ConvertTo-Json -Compress) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
    } catch { [Console]::Error.WriteLine('No se pudo escribir el log del instalador.') }
}
trap {
    Write-InstallEvent 'install_failed' 'error'
    throw
}
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
$logDirectory = Join-Path $state 'logs'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$script:InstallLogPath = Join-Path $logDirectory 'installer.jsonl'
$reportedVersion = & $source --version
if ($LASTEXITCODE -ne 0 -or $reportedVersion -notmatch '^punishell-agent\s+([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?)$') { throw 'Versión de agente inválida.' }
$script:InstallVersion = $Matches[1]
Write-InstallEvent 'install_started'
$target = Join-Path $install 'punishell-agent.exe'
Copy-Item -LiteralPath $source -Destination $target -ErrorAction Stop
Write-InstallEvent 'install_files_copied'
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
    dead_man_seconds = $DeadManSeconds
}
$configPath = Join-Path $install 'agent.json'
[System.IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding($false)))
& icacls.exe $configPath '/inheritance:r' '/grant:r' 'SYSTEM:F' 'Administrators:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'No se pudo proteger agent.json.' }
$code = Read-Host 'Código de activación de un solo uso'
Write-InstallEvent 'install_enrollment_started'
$code | & $target enroll --config $configPath
if ($LASTEXITCODE -ne 0) { throw 'La activación falló; no se creó el servicio.' }
Write-InstallEvent 'install_service_started'
& $target install-service --config $configPath
if ($LASTEXITCODE -ne 0) { throw 'El servicio no se pudo instalar.' }
Write-InstallEvent 'install_completed'
Write-Host "PuniShellAgent instalado y activado. Configuración: $configPath"
