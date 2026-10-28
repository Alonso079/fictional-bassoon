# PuniShell Rust — estado y operación

La implementación nueva está en este workspace. El código Python/PHP y los
instaladores antiguos permanecen en la raíz sólo como referencia de migración:
no deben desplegarse. No se copiaron sus mecanismos de shell arbitrario,
webcam, geolocalización, extracción de claves BitLocker, exclusiones de
Defender, WMI de persistencia, ejecución oculta ni reglas `Deny Delete`.

## Componentes

| Crate | Función |
|---|---|
| `protocol` | Sobre Ed25519 con dominios independientes para dispositivo, servidor, licencia, comando y actualización. |
| `domain` | Roles, aprobación por otra persona, MFA reciente, política de acciones y estados. |
| `licensing` | Licencias de meses naturales (p. ej. 6), revocación, cupo y gracia offline sólo de inventario. |
| `server` | HTTPS, panel, sesiones/CSRF/TOTP, SQLite transaccional, activación, colas, recibos y auditoría. |
| `agent` | Enrolamiento, diario SQLite, check-in firmado, ejecución tipada, recuperación de recibos y actualización. |
| `windows-platform` | DPAPI, red/WLAN/WTS/WMI, bloqueo de sesión, SCM y WinVerifyTrust/Authenticode. |

No hay shell remoto genérico. El panel permite inventario, diagnóstico limitado,
bloqueo de estación, reinicio de servicios permitidos, actualización aprobada
y rotación de identidad. Las acciones administrativas exigen operador solicitante,
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
  --private-key /etc/punishell/privkey.pem
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

Las acciones continúan siendo tipadas: inventario, diagnóstico limitado,
bloqueo de estación, reinicio de servicios permitidos, actualización y rotación
de identidad. BitLocker permite únicamente reanudar protectores existentes en
una unidad validada (`C:`–`Z:`); no inicia cifrado, no suspende protección y no
crea ni lee claves. No se añadió ejecución arbitraria. Solicitud y aprobación siguen
separadas, con TOTP reciente y auditoría encadenada.

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

En el panel HTTPS, iniciar sesión como `admin`, crear cuentas separadas de
`operator` y `approver`, emitir una licencia de `6` meses, con las prestaciones
y cupo deseados, y generar un código de activación. El código tiene un solo uso
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

## Validación y pendientes de despliegue

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
