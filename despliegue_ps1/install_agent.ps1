# ==============================================================================
# PUNISHELL MDM - AGENT DEPLOYMENT SCRIPT (EASTON DESIGN)
# Versión: 2.0 "Cucaracha Atómica" - Blindaje Multicapa Extremo
# ==============================================================================

# 1. VALIDACIÓN DE PRIVILEGIOS
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Error: Se requieren privilegios de Administrador para el blindaje del sistema."
    Exit
}

# Configuración de Rutas Estratégicas
$SafePath     = "C:\Windows\SysWOW64\com\EastonMonitor"  # Residencia Activa
$RescuePath   = "C:\Recovery\EastonResidue"              # Ancla Post-Formateo
$AgentName    = "EastonSystemSvc.exe"                    # Binario con extensión
$ProcName     = "EastonSystemSvc"                        # Nombre del proceso (Sin .exe)
$CurrentDir   = $PSScriptRoot
$SourceExe    = Join-Path $CurrentDir "agente_punishell.exe"

Write-Host "--- Iniciando Despliegue de Blindaje PuniShell ---" -ForegroundColor Cyan

# 2. PREPARACIÓN DE DIRECTORIOS Y EXCLUSIONES
Write-Host "[*] Configurando directorios protegidos..." -ForegroundColor Yellow
if (!(Test-Path $SafePath))   { New-Item -Path $SafePath -ItemType Directory -Force | Out-Null }
if (!(Test-Path $RescuePath)) { New-Item -Path $RescuePath -ItemType Directory -Force | Out-Null }

# Exclusiones de Windows Defender
Add-MpPreference -ExclusionPath $SafePath -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath $RescuePath -ErrorAction SilentlyContinue

# 3. INSTALACIÓN DE BINARIOS
Write-Host "[*] Instalando binarios del agente..."
if (Test-Path $SourceExe) {
    Copy-Item -Path $SourceExe -Destination "$SafePath\$AgentName" -Force
    Copy-Item -Path $SourceExe -Destination "$RescuePath\agente_punishell.exe" -Force
    Copy-Item -Path (Join-Path $CurrentDir "install_agent.ps1") -Destination "$RescuePath\install_agent.ps1" -Force
} else {
    Write-Error "CRÍTICO: No se encontró agente_punishell.exe en $CurrentDir"
    Exit
}

# 4. CAPA 1: SERVICIO DE WINDOWS
Write-Host "[*] Registrando Servicio de Monitoreo de Activos..."
$SvcName = "EastonAssetMonitor"
if (Get-Service -Name $SvcName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
    sc.exe delete $SvcName | Out-Null
}

New-Service -Name $SvcName `
            -BinaryPathName "$SafePath\$AgentName" `
            -DisplayName "Easton Asset Monitoring Service" `
            -StartupType Automatic `
            -Description "Gestiona la telemetría y seguridad de activos para Easton Design." | Out-Null

sc.exe failure $SvcName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

# 5. CAPA 2: ANCLA DE RECUPERACIÓN (SetupComplete)
Write-Host "[*] Configurando Ancla de Recuperación..."
$ScriptsPath = "C:\Windows\Setup\Scripts"
if (!(Test-Path $ScriptsPath)) { New-Item -Path $ScriptsPath -ItemType Directory -Force | Out-Null }

$SetupCompleteContent = @"
@echo off
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "$RescuePath\install_agent.ps1"
exit
"@
$SetupCompleteContent | Out-File -FilePath "$ScriptsPath\SetupComplete.cmd" -Encoding ASCII

# 6. CAPA 3: SEGURO DE VIDA EN REGISTRO
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $RegPath -Name "EastonGuard" -Value "$SafePath\$AgentName" -ErrorAction SilentlyContinue

# 7. CAPA 4: BLINDAJE DE PERMISOS (ACL HARDENING)
Write-Host "[*] Aplicando Inmunidad al borrado (ACL)..." -ForegroundColor Yellow
$Acl = Get-Acl $SafePath
$Acl.SetAccessRuleProtection($true, $false)
$ArSystem = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$ArEveryone = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$ArDenyDelete = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Delete,DeleteSubdirectoriesAndFiles,WriteAttributes", "ContainerInherit,ObjectInherit", "None", "Deny")

$Acl.AddAccessRule($ArSystem)
$Acl.AddAccessRule($ArEveryone)
$Acl.AddAccessRule($ArDenyDelete)
Set-Acl $SafePath $Acl

# 8. CAPA 5: CENTINELA WMI (GHOST MONITOR)
Write-Host "[*] Instalando Centinela WMI..." -ForegroundColor Yellow
$FilterName = "EastonCheckInFilter"
$ConsumerName = "EastonCheckInConsumer"

$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_LocalTime'"
$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name=$FilterName; QueryLanguage="WQL"; Query=$Query}

# Comprobación de proceso corregida (Usa $ProcName sin .exe)
$CommandLine = "powershell.exe -WindowStyle Hidden -Command ""if (!(Get-Process '$ProcName' -ErrorAction SilentlyContinue)) { Start-Process '$SafePath\$AgentName' }"""
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$ConsumerName; CommandLineTemplate=$CommandLine}

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$Filter; Consumer=$Consumer} | Out-Null

# 9. ACTIVACIÓN DE SERVICIOS DE UBICACIÓN
Set-Service -Name "lfsvc" -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Allow" -ErrorAction SilentlyContinue

# 10. EJECUCIÓN Y OCULTAMIENTO FINAL
Write-Host "[*] Iniciando servicio y ocultando rastros..." -ForegroundColor Green
Start-Service -Name $SvcName -ErrorAction SilentlyContinue
attrib +h +s $SafePath
attrib +h +s $RescuePath

Write-Host "--- Blindaje PuniShell Completado con Éxito ---" -ForegroundColor Green