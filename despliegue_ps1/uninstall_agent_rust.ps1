# Retirada explícita del agente Rust. Los datos locales se conservan por defecto.
param([switch]$RemoveData)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecutar como administrador.'
}
$service = Get-Service -Name PuniShellAgent -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name PuniShellAgent -ErrorAction Stop }
    & sc.exe delete PuniShellAgent | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo retirar el servicio.' }
}
$install = Join-Path $env:ProgramFiles 'PuniShell'
$state = Join-Path $env:ProgramData 'PuniShell'
if (Test-Path -LiteralPath $install) { Remove-Item -LiteralPath $install -Recurse -Force -ErrorAction Stop }
if ($RemoveData -and (Test-Path -LiteralPath $state)) { Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction Stop }
Write-Host 'Servicio y binarios retirados.'
if (-not $RemoveData) { Write-Host "Estado local conservado en $state. Usar -RemoveData sólo cuando se haya revocado el agente en el servidor." }
