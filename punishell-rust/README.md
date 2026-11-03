# PuniShell Rust — estado y operación

La implementación nueva está en este workspace. El código Python/PHP y los
instaladores antiguos permanecen en la raíz sólo como referencia de migración:
no deben desplegarse. No se copiaron sus mecanismos de shell arbitrario,
webcam, geolocalización, extracción de claves BitLocker, exclusiones de
Defender, WMI de persistencia, ejecución oculta ni reglas `Deny Delete`.

## Componentes

La compilación, empaquetado, instalación systemd y publicación en GitHub Releases
están detalladas en [el manual de versiones](docs/RELEASES.md). El alcance de
distribución es servidor Linux x64 y agente Windows x64.

| Crate | Función |
|---|---|
| `protocol` | Sobre Ed25519 con dominios independientes para dispositivo, servidor, licencia, comando y actualización. |
| `domain` | Roles, aprobación por otra persona, MFA reciente, política de acciones y estados. |
| `licensing` | Licencias de meses naturales (p. ej. 6), revocación, cupo y gracia offline sólo de inventario. |
| `server` | HTTPS, panel, sesiones/CSRF/TOTP, SQLite transaccional, activación, colas, recibos y auditoría. |
| `agent` | Enrolamiento, diario SQLite, check-in firmado, ejecución tipada, recuperación de recibos y actualización. |
| `windows-platform` | DPAPI, red/WLAN/WTS/WMI, bloqueo de sesión, SCM y WinVerifyTrust/Authenticode. |

No hay shell remoto genérico. El panel permite inventario, bloqueo de estación,
WIPE de laboratorio, actualización aprobada y rotación de identidad. Las acciones
administrativas exigen un solicitante,
aprobador distinto con TOTP y licencia activa. El agente sólo ejecuta comandos
firmados, para su tenant e identidad, dentro de 5 minutos y una sola vez.

## Preparación del servidor

Compilar en Linux con Rust 1.97 o superior:

```bash
cargo build --release -p punishell-server --locked
```

Obtener un certificado HTTPS real para el nombre DNS del servidor y una clave TLS
privada. La URL pública debe coincidir con el origen usado por el panel, sin `/`
final. Para la primera inicialización, `state-dir` y `config` no deben existir:

```bash
./target/release/punishell-server init \
  --config /var/lib/punishell/server.json \
  --state-dir /var/lib/punishell/state \
  --public-url https://mdm.example.org \
  --certificate /etc/punishell/fullchain.pem \
  --private-key /etc/punishell/privkey.pem \
  --license-public-key /etc/punishell/license-public.json
```

El comando pide la contraseña inicial (mínimo 14 caracteres) y presenta **una sola
vez** el secreto TOTP del administrador. Guardar ese secreto en una aplicación
MFA. `state/trust.json` contiene únicamente las claves públicas de cuatro
propósitos; entregarlo a los equipos por un canal confiable, nunca obteniéndolo
a ciegas del mismo servidor en el momento de instalar. La configuración inicial
escucha sólo en `127.0.0.1:8443`: ajustar `bind` y red/proxy TLS según el entorno.
`serve` utiliza TLS directamente; no ofrece HTTP plano:

```bash
./target/release/punishell-server serve --config /var/lib/punishell/server.json
```

## Licencias del proveedor y seis roles

La emisión se realiza **fuera del servidor cliente** con `punishell-license`,
una herramienta del crate `licensing` que no se incluye en el paquete del servidor:

```bash
cargo build --release -p punishell-licensing --bin punishell-license --locked
# En la máquina privada del proveedor, una vez:
./target/release/punishell-license init \
  --key /ruta/privada/license.key --public-key /ruta/publica/license-public.json
# Emitir la suscripción contratada (25 equipos; un mes natural):
./target/release/punishell-license issue \
  --key /ruta/privada/license.key --tenant main --months 1 --max-agents 25 \
  --features inventory,lock_workstation,wipe_data,updates,rotate_identity,manage_bit_locker \
  --output /ruta/entrega/licencia.json
```

Entregar `license-public.json` por un canal confiable para el `init` del servidor,
y `licencia.json` al administrador de plataforma para **Verificar e importar**.
`POST /api/v1/licenses/import` recibe el sobre JSON firmado; comprueba firma,
tenant, producto, vigencia y que la emisión sea posterior a la instalada. No
acepta reimportaciones ni retrocesos. La vista Licencias muestra estado, cupos y
vencimiento. Se eliminaron los endpoints de emisión y revocación locales.
`trust.json` conserva la clave pública del proveedor y las raíces públicas de
servidor, comandos y actualizaciones; nunca contiene claves privadas.

| Rol | Permisos de escritura / lectura especial |
| --- | --- |
| `security_observer` | Dashboard, inventario e incidencias; solo lectura |
| `requester` | Solicitar y cancelar sus órdenes |
| `approver` | Aprobar con TOTP nuevo o rechazar órdenes |
| `technical_operator` | Códigos de activación, revocar agentes y reconocer incidencias |
| `auditor` | Consultar auditoría inmutable |
| `platform_administrator` | Gestionar usuarios e importar licencias; consultar auditoría |

Todos los roles autenticados pueden leer dashboard, agentes e incidencias de su
tenant. El administrador no hereda los permisos de solicitante ni de operador
técnico. La separación Maker-Checker, CSRF y MFA se mantienen.

### Actualizar una instalación existente

Detener el servidor y respaldar su estado antes de desplegar los binarios nuevos.
El servidor rechaza el arranque si encuentra `state/license.key`. Transferir esa
clave a la custodia privada del proveedor y retirarla del cliente conservando su
clave pública en `trust.json`. Si la clave estuvo bajo control del cliente,
rotarla en el proveedor y distribuir la nueva raíz pública a servidor y agentes;
las licencias anteriores necesitarán reemisión bajo esa nueva raíz. No ejecutar
`init` sobre el estado existente ni eliminar la base de datos.

La migración automática `0007_formal_roles.sql` convierte `administrator` a
`platform_administrator` y `operator` a `requester`; mantiene aprobadores y
auditores. Conserva identidades, hashes, MFA, sesiones y referencias de órdenes
e incidencias, y verifica las claves foráneas antes del commit. Crear las cuentas
adicionales de operador técnico y observador desde el panel o `add-user`.

Actualizar servidor y agentes juntos: las órdenes remotas `diagnostic_bundle`
y `restart_managed_service` se rechazan. Los indicadores antiguos `diagnostics`
y `manage_services` se conservan solo para leer licencias firmadas existentes y
no habilitan ninguna acción. `managed_services` en configuraciones anteriores
se acepta por compatibilidad y ya no autoriza reinicios.

## WIPE del piloto y bloqueo sin conexión

`wipe_data` exige la prestación `wipe_data`, solicitud y aprobación independiente.
Su único parámetro válido es `authorized_path: "C:\\PuniShell_Lab_Data"`. Solo
elimina archivos regulares situados directamente en esa carpeta; no formatea,
no realiza borrado seguro criptográfico y no recorre subcarpetas. Rechaza otras
rutas, enlaces y junctions. El resultado se reporta y registra en la auditoría
habitual de órdenes. Si el sistema de archivos falla durante el borrado puede
haber eliminación parcial; se reporta fallo y no se repite automáticamente.

Crear la carpeta de prueba desde PowerShell elevado y protegerla antes de usarla:

```powershell
New-Item -ItemType Directory -Path 'C:\PuniShell_Lab_Data'
icacls.exe 'C:\PuniShell_Lab_Data' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
Set-Content -LiteralPath 'C:\PuniShell_Lab_Data\prueba.txt' -Value 'Datos de ensayo'
```

El agente tiene un Dead Man's Switch con `dead_man_seconds` en `agent.json`:
por defecto **259200 segundos (72 horas)**; para la presentación usar **120**.
El instalador admite `-DeadManSeconds 120`. El rango permitido es 60–259200.
El último contacto autenticado queda persistido en `journal.db`; reiniciar el
servicio no reinicia el plazo. También utiliza tiempo monotónico durante la
ejecución y bloquea preventivamente si el reloj retrocede antes del último
contacto. Revisa el plazo antes de cada petición y durante las esperas de reintento.
Las peticiones HTTPS tienen un timeout de 30 segundos.

Al vencer el plazo bloquea la sesión interactiva mediante el mecanismo nativo
existente (el servicio invoca el proceso que llama `LockWorkStation`). Mientras
continúe sin contacto, reintenta como máximo una vez por minuto; un fallo de
bloqueo no detiene el agente. Registra `dead_man_lock` y su resultado en el log
operativo local. Un contacto válido restablece el temporizador; no desbloquea
la sesión automáticamente. En Linux las operaciones de bloqueo y WIPE devuelven
`WindowsRequired`; comprobar su efecto real en Windows antes del despliegue.

## Laboratorio sin DNS: dirección IP manual

Se puede utilizar una IP LAN estática o reservada, por ejemplo
`192.168.1.50`, y el puerto `8443`. Sustituir esa IP en todos los ejemplos por
la dirección real del host Linux. Servidor y equipos deben tener conectividad
LAN o VPN; `127.0.0.1` en Windows apunta al propio Windows. El agente inicia las
conexiones salientes y no necesita un puerto entrante en Windows.

### HTTPS con una CA local de laboratorio

En Linux, crear un directorio privado fuera del repositorio. Estos comandos
generan una CA de ensayo y un certificado de servidor con la IP en su extensión
SAN; ejecutarlos una sola vez para ese laboratorio. OpenSSL debe estar instalado.
Las claves sin contraseña se protegen mediante permisos y deben permanecer
únicamente en el host de laboratorio.

```bash
lab_dir="$HOME/.local/share/punishell-lab"
install -d -m 700 "$lab_dir"
cd "$lab_dir"
umask 077

openssl req -x509 -newkey rsa:3072 -noenc -sha256 -days 365 \
  -keyout lab-ca.key -out lab-ca.pem -subj '/CN=PuniShell Lab CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

openssl req -new -newkey rsa:3072 -noenc -sha256 \
  -keyout server.key -out server.csr -subj '/CN=PuniShell Lab Server' \
  -addext 'subjectAltName=IP:192.168.1.50' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=serverAuth'

openssl x509 -req -in server.csr -CA lab-ca.pem -CAkey lab-ca.key \
  -CAcreateserial -out server.pem -days 90 -sha256 -copy_extensions copy
openssl verify -CAfile lab-ca.pem -verify_ip 192.168.1.50 server.pem
```

Desde `punishell-rust/`, después de compilar, inicializar con esa misma URL:

```bash
./target/release/punishell-server init \
  --config "$lab_dir/server.json" \
  --state-dir "$lab_dir/state" \
  --public-url https://192.168.1.50:8443 \
  --certificate "$lab_dir/server.pem" \
  --private-key "$lab_dir/server.key" \
  --license-public-key /ruta/recibida/license-public.json
```

Antes de ejecutar `serve`, editar **sólo** `bind` en el `server.json` generado
para usar `192.168.1.50:8443` en lugar de `127.0.0.1:8443`. Esa IP debe estar
asignada a una interfaz del servidor. Conservar el resto de la configuración y
permitir TCP 8443 en el firewall del host para la subred de pruebas.

```bash
./target/release/punishell-server serve --config "$lab_dir/server.json"
```

Desde otra terminal Linux:

```bash
curl --fail --cacert "$lab_dir/lab-ca.pem" \
  https://192.168.1.50:8443/health/ready
```

El navegador usado para el panel también debe confiar en la CA de laboratorio.
Importar únicamente `lab-ca.pem` en el almacén de confianza correspondiente al
navegador o sistema de pruebas. Acceder exactamente a
`https://192.168.1.50:8443`, igual que `public_url`, porque se comprueba el origen
de las peticiones del panel. No se necesita desactivar la validación TLS.

### Paquete y conexión del cliente

Preparar en Windows una carpeta con el agente Rust firmado, el instalador
`install_agent_rust.ps1`, `state/trust.json` del servidor y `lab-ca.pem`.
No copiar `lab-ca.key`, `server.key` ni las claves privadas de `state/`.
En PowerShell elevado, desde esa carpeta:

```powershell
Test-NetConnection -ComputerName 192.168.1.50 -Port 8443

.\install_agent_rust.ps1 `
  -AgentExe .\punishell-agent.exe `
  -TrustPath .\trust.json `
  -ServerUrl https://192.168.1.50:8443 `
  -Tenant main `
  -SignerCertificateSha256 <sha256-del-certificado-de-firma-del-exe> `
  -CaCertificate .\lab-ca.pem

Get-Service PuniShellAgent
```

El instalador solicita el código de activación y escribe manualmente esa URL en
`%ProgramFiles%\PuniShell\agent.json`. La confianza TLS del agente usa el PEM
indicado; la firma Authenticode del EXE debe ser válida para Windows por separado.
Si se usa un certificado de firma de ensayo, provisionar su cadena de confianza
en las máquinas de laboratorio antes de instalar.

Si la IP cambia, emitir un certificado SAN para la nueva dirección y actualizar
`bind`, `public_url` y el `server_url` de los clientes, deteniendo y reiniciando
los servicios correspondientes. Actualizar `server-ca.pem` en los clientes sólo
si cambió la CA. Conservar la identidad DPAPI del agente y las claves del servidor;
no reinicializar ni reenrolar para un mero cambio de dirección.

Antes de las pruebas Windows, comprobar además: reloj sincronizado, edición de
Windows compatible con BitLocker, TPM listo para el escenario ensayado,
permisos del proveedor WMI, licencia con `manage_bit_locker`, y usuarios separados
para solicitar y aprobar. El inventario básico no requiere TPM. El servidor
actual no proporciona descubrimiento de red ni cambio automático de dirección.

## Operación y telemetría del prototipo

El panel incluye un resumen de flota, equipos online, señales atrasadas, equipos
offline, solicitudes pendientes, acciones en curso, fallos recientes y vigencia
de licencia. La ficha de cada equipo presenta inventario, actividad reciente y
tendencias de disco, memoria y errores para las últimas 24 horas.

Cada heartbeat autorizado conserva una muestra numérica de telemetría. El
servidor retiene hasta 30 días y un máximo de 5.000 muestras por equipo; la
limpieza ocurre dentro de la misma transacción del heartbeat. Un equipo se marca
`online` hasta 2 minutos desde el último contacto, `stale` entre 2 y 15 minutos y
`offline` después de 15 minutos. Estos umbrales operativos son del prototipo y
deben alinearse con el intervalo real de polling antes de producción.

Las acciones continúan siendo tipadas: inventario, bloqueo de estación,
WIPE de laboratorio, actualización y rotación
de identidad. BitLocker permite únicamente reanudar protectores existentes en
una unidad validada (`C:`–`Z:`); no inicia cifrado, no suspende protección y no
crea ni lee claves. No se añadió ejecución arbitraria. Solicitud y aprobación siguen
separadas, con TOTP reciente y auditoría encadenada.

### Centro de incidencias

El panel **Incidencias** conserva episodios de problemas por equipo y tipo,
con severidad, primera detección, última evaluación, fecha de la evidencia y
responsable de reconocimiento. El resumen muestra cuántas están activas y
cuántas esperan reconocimiento. Las vistas de activas, resueltas e historial
completo se paginan en bloques de 100.

En esta primera versión, las reglas son fijas:

- `agent_offline`: sin contacto durante más de 15 minutos, severidad crítica.
- `disk_low`: menos de 10% de disco libre, severidad de advertencia.
- `bitlocker_unprotected`: algún volumen reporta protección `off`, crítica.

La evaluación corre dentro del mantenimiento cada minuto. Una incidencia activa
se actualiza sin duplicarse y mantiene su reconocimiento. Solo el operador
técnico puede reconocerla; todos los roles autenticados pueden leer
las incidencias de su tenant. Reconocer no ejecuta acciones ni prueba recuperación.
No se permite cerrar manualmente una incidencia como si se hubiese reparado.

Para resolver problemas de disco y BitLocker se necesita inventario posterior a
la evidencia del fallo, con antigüedad máxima de dos minutos. Los datos ausentes,
desconocidos o con errores de BitLocker no prueban recuperación. Revocar el
equipo cierra sus incidencias con una razón específica de salida del monitoreo.
Una recaída crea otro episodio y conserva el historial anterior. Apertura,
reconocimiento, recuperación y cierre por revocación quedan auditados.

API: `GET /api/v1/incidents?state=active&offset=0` (estados `active`, `open`,
`acknowledged`, `resolved`, `all`) y
`POST /api/v1/incidents/{id}/acknowledge`, con sesión y CSRF. El esquema SQLite
se actualiza automáticamente de versión 4 a 5 de forma transaccional.

La resolución de una incidencia describe la recuperación del equipo; la
verificación de una acción BitLocker se registra además en su comando específico.
Quedan para siguientes incrementos las reglas configurables por grupos, varias
muestras consecutivas, ventanas de mantenimiento y notificaciones externas.

### Verificación posterior de BitLocker

Cuando el agente completa correctamente `resume_bit_locker_protection`, el
resultado de ejecución queda `succeeded` y se inicia una verificación separada
`pending`. Se guarda la secuencia de la confirmación y se esperan hasta 15
minutos por un heartbeat posterior con información del volumen exacto solicitado.
El inventario que ya estaba almacenado no verifica el comando, aunque indicara
protección activa. Las acciones fallidas y las de otros tipos no abren esta
verificación; los comandos históricos anteriores a esta función quedan sin ella.

El panel **Solicitudes y resultados** y la API de comandos exponen por separado
la ejecución y `verification`:

- `pending`: esperando evidencia; una lectura `off` no termina anticipadamente
  la ventana, para permitir la confirmación en un heartbeat siguiente.
- `verified`: el volumen solicitado informa protección `on`, sin errores, en
  un heartbeat de secuencia superior a la confirmación del comando.
- `not_verified`: vencieron los 15 minutos y la última lectura válida fue `off`.
- `inconclusive`: venció el plazo sin evidencia suficiente o el equipo fue
  revocado antes de confirmar.

Las lecturas de otra unidad, duplicadas, desconocidas, ausentes o con errores
no confirman el resultado. El plazo se revisa en el mantenimiento periódico;
un heartbeat recibido fuera de plazo no puede cambiar la conclusión. Se guardan
la fecha de observación y el detalle, y las transiciones quedan auditadas en la
misma transacción. Los reintentos del agente no reinician la verificación ni
duplican su confirmación.

`verified` acredita una observación posterior de protección activa; no garantiza
que ésta se mantenga indefinidamente ni demuestra que el comando haya causado
el cambio. Las incidencias siguen vigilando su estado. El servidor no reejecuta
automáticamente acciones que no se pudieron verificar.

El esquema SQLite pasa de versión 5 a 6 mediante migración transaccional.

### Ejecución del mantenimiento

`serve` ejecuta mantenimiento al arrancar y cada 60 segundos. Actualiza los
comandos vencidos aunque sus agentes estén offline y registra un evento
`command_expired` por comando dentro de la misma transacción. Un comando
`claimed` que vence puede haber iniciado su ejecución: `expired` no demuestra
que Windows haya cancelado la operación. Se conserva su lease y el servidor
todavía admite un resultado tardío por el flujo normal de recibos.

La tarea elimina sesiones, desafíos de enrolamiento, códigos de activación y
tokens de recuperación de contraseña vencidos, además de límites de intentos
inactivos durante más de un día. Respeta las referencias entre desafíos y
códigos. También elimina telemetría anterior a 30 días para equipos que ya no
envían heartbeats. Los recibos anti-replay, identidades, comandos y auditoría
se conservan. El límite de 5.000 muestras por agente sigue aplicándose al recibir
cada heartbeat.

Para ejecutar el mismo mantenimiento manualmente desde el host del servidor:

```bash
./target/release/punishell-server maintenance \
  --config /var/lib/punishell/server.json
```

El comando devuelve JSON con los conteos afectados. `serve` emite los mismos
conteos en registros JSON con `event=maintenance`; los fallos usan
`event=maintenance_failed` y se reintentan en el siguiente ciclo. Un fallo de
mantenimiento inicial impide comenzar a aceptar tráfico.

`/health/live` informa si el proceso responde. `/health/ready` comprueba acceso
a SQLite y versión de esquema con espera máxima de dos segundos; devuelve
HTTP 503 con `status=not_ready` si la comprobación falla. No requiere sesión ni
expone rutas o detalles internos. Esto comprueba la dependencia de base de datos,
no la salud de los endpoints Windows ni la vigencia de sus licencias.

En Unix, `SIGTERM` y Ctrl+C inician un cierre ordenado con hasta diez segundos
para drenar peticiones HTTPS. Después se detiene el mantenimiento y se cierra
el pool SQLite. Esto permite detener el proceso mediante un supervisor como
systemd o un contenedor.

### BitLocker

En Windows, el agente consulta el proveedor oficial
`Win32_EncryptableVolume` en modo de solo lectura. Por cada volumen informa
letra de unidad, protección activa/inactiva, estado y porcentaje de conversión,
método de cifrado, bloqueo y auto-unlock. El resumen operativo alerta sobre
volúmenes sin protección y conserva los conteos en el historial de telemetría.

Esta integración no extrae ni transmite contraseñas de recuperación. Habilitar
cifrado desde cero, suspender protección o custodiar recovery keys requiere un flujo de
escrow separado, almacenamiento cifrado con acceso de emergencia, rotación,
auditoría específica y pruebas en hardware Windows con TPM; no debe mezclarse
con el inventario periódico.

En el panel HTTPS, iniciar sesión como `admin`, importar la licencia firmada
entregada por el proveedor y crear cuentas separadas de `requester`, `approver`
y `technical_operator`. El operador técnico genera el código de activación. El código tiene un solo uso
y TTL elegido (1–1440 minutos); el período de seis meses corresponde a la
licencia, no al código. El servidor también soporta CLI `add-user`, `add-tenant`,
`reset-password`, `publish-update` y `verify-audit` (`--help` en cada comando).

## Agente Windows y firma de código

Compilar en una máquina Windows con toolchain MSVC y Windows SDK:

```powershell
cargo build --release -p punishell-agent --target x86_64-pc-windows-msvc --locked
```

Firmar **cada EXE de release** con un certificado de editor de código válido,
por ejemplo con SignTool del Windows SDK (SHA-256 y sellado de tiempo):

```powershell
signtool sign /fd SHA256 /tr https://timestamp.digicert.com /td SHA256 /a punishell-agent.exe
signtool verify /pa /v punishell-agent.exe
```

El certificado del ejecutable Python original no firma el Rust nuevo y no
concede su clave privada. Para fijar el certificado hoja en el instalador:

```powershell
$s = (Get-AuthenticodeSignature .\punishell-agent.exe).SignerCertificate
$h = [Security.Cryptography.SHA256]::Create()
try { ([BitConverter]::ToString($h.ComputeHash($s.RawData))).Replace('-','').ToLowerInvariant() } finally { $h.Dispose() }
```

Instalar con PowerShell elevado y un paquete recibido por canal confiable. El
script comprueba Authenticode y el pin del certificado, protege las ACL, copia
el EXE, crea `agent.json` con las raíces públicas, usa el código de un solo uso
desde entrada estándar, registra un servicio visible y lo inicia:

```powershell
.\despliegue_ps1\install_agent_rust.ps1 -AgentExe .\punishell-agent.exe `
  -TrustPath .\trust.json -ServerUrl https://mdm.example.org `
  -Tenant main -SignerCertificateSha256 <sha256-del-certificado>
```

Si se usa CA privada, añadir `-CaCertificate .\ca.pem`. La configuración final
reside en `%ProgramFiles%\PuniShell\agent.json`, el estado y la clave protegida
por DPAPI en `%ProgramData%\PuniShell`. No se almacena el código de activación.
Para retirar el agente, usar `uninstall_agent_rust.ps1`; por defecto preserva
el estado y sólo `-RemoveData` lo borra tras revocar el equipo en el panel.

## Actualizaciones y límites de seguridad

`publish-update` admite un PE `MZ` de hasta 64 MiB y un número SemVer mayor.
El servidor firma el manifiesto Ed25519; el agente verifica la firma de
actualización, canal, versión, tamaño, SHA-256 del archivo y Authenticode con
pin del editor antes de preparar el helper. El helper hace copia de seguridad,
detiene el servicio, reemplaza el EXE, espera `health.json` de la versión nueva
y revierte si no hay check-in saludable. El servidor no puede falsificar por sí
solo una firma de código Windows válida del editor.

La firma del comando **no sustituye TLS**. El agente mantiene cuatro trust stores
distintos, rechaza redirecciones y requiere HTTPS. Tras el enrolamiento, agente y
servidor cifran además cada sobre firmado con AES-256-GCM, usando claves por
dispositivo y contexto autenticado distinto para cada dirección. La clave se
provisiona sólo dentro de la respuesta HTTPS firmada, se guarda con DPAPI en el
agente y cifrada con la clave maestra en el servidor. Los recibos que pueden
contener la provisión también se cifran en reposo. Esta capa reduce exposición en
proxies, colas y registros, pero no permite retirar HTTPS.

El payload JSON se firma como bytes base64url exactos; no se reserializa ni se
proclama JCS. El diario y los recibos transaccionales reducen replay, pero ningún sistema distribuido promete
ejecución física exactamente una vez si se pierde la confirmación del sistema
operativo. Acciones en estado `running` al reiniciar se reportan como inciertas,
sin repetirse automáticamente.

Al abrir una base de datos con esquema 1, el servidor aplica de forma transaccional
la migración 2 para agregar las claves de transporte. Los agentes ya enrolados se
actualizan gradualmente: el agente nuevo anuncia soporte mediante el encabezado
`x-punishell-transport`, recibe su clave en el último intercambio firmado sin
cifrar y el servidor rechaza cualquier downgrade posterior. Un agente antiguo no
anuncia esa capacidad, por lo que puede seguir comunicándose mientras se completa
el despliegue escalonado.

## Logs y diagnóstico de pruebas

El agente registra eventos JSONL en `%ProgramData%\PuniShell\logs\agent.jsonl`.
El archivo rota al alcanzar 1 MiB y conserva cuatro archivos anteriores
(`agent.1.jsonl` a `agent.4.jsonl`). Un lock entre procesos coordina el servicio,
la consola y el helper de actualización. En Windows se heredan las ACL del
directorio de estado, restringidas por el instalador a SYSTEM y Administrators;
en Unix se usan directorios 0700 y archivos nuevos 0600.

Se registran inicio/parada, enrolamiento, peticiones, duración, errores de
conexión, reintentos y próxima espera, ejecución/rechazo de acciones, preparación
de actualización y confirmación o intento de rollback. Cada registro contiene
fecha UTC, nivel, versión y, cuando corresponde, identificadores de agente,
petición y comando. Las peticiones incluyen host/IP y puerto del servidor,
sin usuario, contraseña, ruta ni query string.

Las categorías distinguen timeout, DNS, TLS, conexión, HTTP, SQLite, plataforma,
protocolo, licencia, política y configuración. DNS/TLS se clasifican según las
causas disponibles en la biblioteca HTTP: algunos errores pueden quedar en una
categoría más general. Los cuerpos de mensajes, códigos de activación, claves,
cookies, tokens y texto arbitrario de excepciones no se escriben en estos logs.
Los errores detallados WMI siguen disponibles en el inventario autorizado.

Un fallo al escribir el log se avisa por stderr sin provocar reejecución de una
acción. Los errores fatales del servicio también se registran en este directorio
cuando se puede escribir en ProgramData; ya no se sobrescribe un único
`service-error.log`. El instalador escribe `installer.jsonl`, con un archivo
anterior de hasta 1 MiB, desde que valida el ejecutable y prepara las ACL. Los
fallos previos a esa fase se muestran en consola. No usa una transcripción de
PowerShell que pudiera guardar el código de activación.

Para observar el cliente desde PowerShell elevado:

```powershell
Get-Content "$env:ProgramData\PuniShell\logs\agent.jsonl" -Tail 40 -Wait
Get-Content "$env:ProgramData\PuniShell\logs\installer.jsonl" -Tail 40
```

Exportar un diagnóstico local, incluso si la configuración o la identidad del
agente no se pueden abrir:

```powershell
& "$env:ProgramFiles\PuniShell\punishell-agent.exe" export-diagnostics `
  --state-dir "$env:ProgramData\PuniShell" `
  --output "$env:TEMP\punishell-diagnostic.json"
```

La exportación conserva los últimos 200 eventos válidos del agente e instalador,
ordenados por fecha, y cuenta las entradas descartadas. Lee únicamente los
nombres de log conocidos, con límites de tamaño, valida el esquema y excluye
entradas con campos desconocidos. No copia `agent.json`, identidades, SQLite,
inventario ni claves. Rechaza sobrescribir el destino. El archivo sí contiene
identificadores y direcciones del servidor: revisarlo antes de compartirlo.
La exportación es local y no se envía automáticamente a terceros.

En el servidor, los logs HTTP incluyen fecha UTC, nivel, versión, duración,
categoría de fallo, `request_id` propio y `client_request_id` para correlacionar
con el cliente. Se registra el patrón de ruta, no queries ni rutas desconocidas
arbitrarias. Este último identificador procede de un encabezado validado sintácticamente y
sirve sólo como pista de diagnóstico, no como identidad autenticada. La auditoría
de seguridad continúa siendo un registro separado en SQLite.

```bash
sudo journalctl -u punishell-server -f
sudo journalctl -u punishell-server --since "30 minutes ago" --no-pager
```

La retención del journal depende de la configuración del host; no se crea un
segundo archivo rotativo para el servidor. Para probar, usar una IP inaccesible,
una CA incorrecta, un código de activación vencido y una acción no permitida en
el laboratorio, y comprobar categorías, reintentos y auditoría. Estas funciones
requieren recompilar los binarios; no modifican paquetes ya generados.

## Validaciones automatizadas

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
cargo check -p punishell-windows-platform --target x86_64-pc-windows-msvc --locked --offline
```

Las pruebas Linux incluyen un flujo HTTP de enrolamiento firmado, código de un
uso, rechazo de secuencia repetida, login TOTP y emisión de licencia de seis
meses. La capa nativa compila para el target Windows. La compilación completa
MSVC y las pruebas del servicio/WinVerifyTrust/rollback deben hacerse en Windows
con Windows SDK, certificados de prueba y máquinas de ensayo. No se ha
desplegado producción ni emitido certificado de código real en este workspace.
