# ==============================================================================
# PUNISHELL MDM - SCRIPT DE EUTANASIA (DESINSTALACIÓN)
# Este script revierte todas las capas de persistencia y elimina los binarios.
# ==============================================================================

# 1. VALIDACIÓN DE PRIVILEGIOS
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Se requiere ejecutar como Administrador para eliminar el blindaje."
    Exit
}

$SafePath   = "C:\Windows\SysWOW64\com\EastonMonitor"
$RescuePath = "C:\Recovery\EastonResidue"
$SvcName    = "EastonAssetMonitor"

Write-Host "--- Iniciando Desactivación de PuniShell ---" -ForegroundColor Red

# 2. ELIMINAR EL CENTINELA WMI (GHOST MONITOR)
# Esto es vital para que el proceso no resucite mientras intentamos borrarlo.
Write-Host "[*] Eliminando persistencia WMI..."
$Namespace = "root\subscription"
Get-WmiObject -Namespace $Namespace -Class __EventFilter -Filter "Name='EastonCheckInFilter'" | Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace $Namespace -Class CommandLineEventConsumer -Filter "Name='EastonCheckInConsumer'" | Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace $Namespace -Class __FilterToConsumerBinding -Filter "Filter=""__EventFilter.Name='EastonCheckInFilter'""" | Remove-WmiObject -ErrorAction SilentlyContinue

# 3. DETENER Y ELIMINAR EL SERVICIO
Write-Host "[*] Deteniendo servicio del sistema..."
Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
sc.exe delete $SvcName | Out-Null

# 4. MATAR PROCESOS ACTIVOS
Write-Host "[*] Terminando procesos del agente..."
Stop-Process -Name "EastonSystemSvc" -Force -ErrorAction SilentlyContinue

# 5. REVERTIR ACL HARDENING (EL PASO CRÍTICO)
# Para poder borrar, primero debemos quitar la regla de "Deny Delete".
Write-Host "[*] Restaurando permisos de carpetas protegidas..."
if (Test-Path $SafePath) {
    # Tomamos propiedad de la carpeta para asegurar el control
    takeown /f $SafePath /r /d s | Out-Null
    # Reseteamos los permisos a los valores por defecto de Windows
    icacls $SafePath /reset /t /c /l /q | Out-Null
}

# 6. LIMPIEZA DE ARCHIVOS Y REGISTRO
Write-Host "[*] Eliminando binarios y llaves de registro..."
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EastonGuard" -ErrorAction SilentlyContinue
Remove-Item -Path $SafePath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $RescuePath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Setup\Scripts\SetupComplete.cmd" -Force -ErrorAction SilentlyContinue

# 7. LIMPIEZA DE DEFENDER
Write-Host "[*] Eliminando exclusiones de seguridad..."
Remove-MpPreference -ExclusionPath $SafePath -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionPath $RescuePath -ErrorAction SilentlyContinue

Write-Host "--- Sistema Limpio: PuniShell ha sido erradicado ---" -ForegroundColor Green