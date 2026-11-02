# Package an already-built agent; signing happens before hashing or packaging.
param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [switch]$AllowUnsigned
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$source = (Resolve-Path -LiteralPath $Executable).Path
$reported = & $source --version
if ($LASTEXITCODE -ne 0 -or $reported -notmatch '^punishell-agent\s+([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?)$') {
    throw 'El ejecutable no informa una versión válida de punishell-agent.'
}
$version = $Matches[1]
if ($env:RELEASE_TAG -and $env:RELEASE_TAG -ne "v$version") { throw 'Tag y versión del agente no coinciden.' }
$signature = Get-AuthenticodeSignature -LiteralPath $source
$signed = $signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate
if (-not $signed -and (-not $AllowUnsigned -or $signature.Status -ne 'NotSigned')) {
    throw 'Se exige Authenticode válido, o -AllowUnsigned para un binario sin firma de laboratorio.'
}
$suffix = if ($signed) { '' } else { '-unsigned' }
$name = "punishell-agent-$version-windows-x86_64$suffix"
$output = Join-Path $repo 'dist'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$archive = Join-Path $output "$name.zip"
$rawExe = Join-Path $output "$name.exe"
foreach ($path in @($archive,$rawExe,"$archive.sha256","$rawExe.sha256")) {
    if (Test-Path -LiteralPath $path) { throw "El artefacto ya existe: $path" }
}
$stage = Join-Path $output ('.windows-package-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage 'punishell-agent.exe')
    foreach ($file in @('install_agent_rust.ps1','uninstall_agent_rust.ps1')) {
        Copy-Item -LiteralPath (Join-Path $repo "despliegue_ps1\$file") -Destination $stage
    }
    Copy-Item -LiteralPath (Join-Path $repo 'punishell-rust\docs\RELEASES.md') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $repo 'punishell-rust\README.md') -Destination $stage
    if ($signed) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $pin = ([BitConverter]::ToString($sha.ComputeHash($signature.SignerCertificate.RawData))).Replace('-','').ToLowerInvariant() }
        finally { $sha.Dispose() }
        Set-Content -LiteralPath (Join-Path $stage 'signer-certificate-sha256.txt') -Value $pin -Encoding ascii
    } else {
        Set-Content -LiteralPath (Join-Path $stage 'UNSIGNED.txt') -Value 'Binario de laboratorio sin firma. Firmar y volver a empaquetar antes de instalar; el instalador exige Authenticode valido.' -Encoding ascii
    }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive
    Copy-Item -LiteralPath $source -Destination $rawExe
    foreach ($path in @($archive,$rawExe)) {
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content -LiteralPath "$path.sha256" -Value "$hash  $([IO.Path]::GetFileName($path))" -Encoding ascii
    }
    Write-Host "Paquete: $archive; Authenticode valido: $signed"
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
