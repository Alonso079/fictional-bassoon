===============================================================================
                   PUNISHELL MDM - MANUAL DE DESPLIEGUE COMPLETO
                          PROYECTO: EASTON DESIGN IT
===============================================================================

AVISO (11-10-2026): ESTE MANUAL DESCRIBE LA VERSIÓN PYTHON/PHP LEGADA Y NO
DEBE USARSE PARA UN DESPLIEGUE NUEVO. CONTIENE MECANISMOS INSEGUROS Y
DESACTUALIZADOS. LA MIGRACIÓN RUST Y LOS PASOS VIGENTES SE ENCUENTRAN EN
punishell-rust/README.md. EL CÓDIGO LEGADO SE CONSERVA PARA AUDITORÍA.

===============================================================================

1. DESCRIPCIÓN GENERAL
-------------------------------------------------------------------------------
PuniShell es un agente de administración remota (MDM) para entornos Workgroup.
Permite telemetría de hardware, extracción de llaves BitLocker, monitoreo 
visual vía webcam, geolocalización y ejecución de comandos remotos.

2. REQUISITOS DEL SISTEMA
-------------------------------------------------------------------------------
- Servidor: XAMPP o Laragon (Apache, MySQL, PHP 8.1+)
- Agente: Windows 10/11 con Python 3.12+
- Dependencias: OpenCV (Webcam), Requests (API), PyInstaller (Compilación)
- Permisos: Administrador del sistema

3. CONFIGURACIÓN DEL SERVIDOR (BACKEND)
-------------------------------------------------------------------------------
1. Iniciar Apache y MySQL en el panel de control (XAMPP).
2. Crear base de datos 'punishell_db' en phpMyAdmin.
3. Importar el siguiente esquema SQL:

   CREATE TABLE easton_endpoints (
     id INT AUTO_INCREMENT PRIMARY KEY,
     hostname VARCHAR(255),
     local_ip VARCHAR(50),
     public_ip VARCHAR(50),
     mac_address VARCHAR(100) UNIQUE,
     bios_serial VARCHAR(255) UNIQUE,
     logged_user VARCHAR(255),
     os_version VARCHAR(255),
     ram_gb FLOAT,
     disk_free_gb FLOAT,
     bitlocker_recovery_key TEXT,
     last_webcam_shot LONGBLOB NULL,
     last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
   );

   CREATE TABLE endpoint_commands (
     id INT AUTO_INCREMENT PRIMARY KEY,
     endpoint_id INT,
     command_string TEXT,
     status ENUM('pending', 'executed', 'failed') DEFAULT 'pending',
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );

4. Ubicar archivos PHP en: C:\xampp\htdocs\backend_php\

4. CONFIGURACIÓN DEL ENTORNO DE DESARROLLO (AGENTE)
-------------------------------------------------------------------------------
Ejecutar estos comandos en la terminal (PowerShell) dentro de la carpeta raíz:

# A. Habilitar ejecución de scripts (SOLUCIÓN AL ERROR DE SEGURIDAD)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# B. Crear y activar el entorno virtual
python -m venv punishell_env
.\punishell_env\Scripts\activate

# C. Instalación masiva de librerías
pip install opencv-python pyinstaller requests
pip install opencv-python

# D. Ejecución en modo pruebas (Check-in manual)
python agente_punishell.py

5. COMPILACIÓN Y PERSISTENCIA (PRODUCCIÓN)
-------------------------------------------------------------------------------
1. Generar el binario silencioso:
   pyinstaller --onefile --noconsole --name "agente_punishell" agente_punishell.py

2. Kit de Instalación (WinRAR SFX):
   - Incluir: agente_punishell.exe (de carpeta dist) + install_agent.ps1
   - Setup: powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File install_agent.ps1
   - Configuración: Ocultar todo / Solicitar acceso administrativo.

6. ACCESO AL PANEL DE CONTROL
-------------------------------------------------------------------------------
URL Dashboard: http://localhost/backend_php/index.php

7. COMANDOS DE PRUEBA RÁPIDA
-------------------------------------------------------------------------------
Desde la Terminal Pro del Dashboard, escribir:

- Notificación visual: 
  msg * "TEASTEANDO PUNISHELL....."

- Cierre forzado de proceso: 
  taskkill /F /IM msedge.exe /T

- Mensaje con PowerShell (PresentationFramework):
  powershell -WindowStyle Hidden -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('OK', 'PuniShell', 'OK', 'Information')"

-------------------------------------------------------------------------------
DESARROLLADO POR: J. SURA ROBLES
ANÁLISIS DE TI - EASTON DESIGN
===============================================================================
