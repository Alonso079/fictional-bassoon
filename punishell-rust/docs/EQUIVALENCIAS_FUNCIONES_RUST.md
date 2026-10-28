# Correspondencia funcional de PuniShell con Rust

Fecha: 11 de octubre de 2026. Fuente funcional: código Python, PHP, JavaScript,
SQL y PowerShell presente en `/home/diogenes/Desktop/PuniShell_Proyect-main`.

Esta correspondencia permite comprobar la nueva versión por función.
**Implementada (sin validar en Windows)** significa código Rust presente y compilado
o probado en Linux; no acredita su operación en un equipo Windows real.
**Pendiente** significa capacidad aún no implementada o prueba de aceptación restante.
**Sustituida** significa conservar el propósito mediante un flujo más controlado.
**Retirada** identifica mecanismos que no forman parte de la versión nueva.

## 1 Estado de esta entrega

El workspace contiene seis crates: `protocol`, `domain`, `licensing`, `server`,
`agent` y `windows-platform`. El servidor HTTPS/SQLite y el agente compilados en
Linux tienen pruebas de integración; la capa nativa se comprueba con el target
Windows, pero no se ha ejecutado en Windows ni firmado un binario de release.
La tabla conserva el inventario histórico y señala los cambios de contrato.

| Capa | Archivos existentes relacionados | Cambio y patrón | Compilación y despliegue |
|---|---|---|---|
| Mensajes | `agente_python/agente_punishell.py`, `backend_php/poll.php` | `protocol`: sobres firmados por propósito | Integrado en servidor y agente |
| Permisos y estados | `solicitar_accion.php`, `autorizar_accion.php`, `endpoint_commands` | `domain` y `server`: reglas, transacciones y recibos | Pruebas unitarias y HTTP/SQLite |
| Activación | `ESPECIFICACION_RUST_ACTIVACION.md` | `licensing` y `server`: meses naturales, código de un uso, cupo | Flujo de integración probado |
| Windows | Agente e instaladores actuales | `windows-platform`, servicio SCM y scripts Rust | Cross-check de la capa nativa; ejecución Windows pendiente |
| Documentación | Informe maestro y especificación existentes | Contratos, operación y límites | Word y documentación Cargo actualizados |

## 2 Equivalencias de las 19 funciones del agente

Fuente: `agente_python/agente_punishell.py`. Los nombres de función de la tercera
columna describen equivalentes funcionales, no necesariamente símbolos públicos
idénticos a los del código Rust.

| ID | Función Python y línea | Equivalente Rust | API o contrato | Estado |
|---|---|---|---|---|
| A01 | `__init__` L16 | `agent::Config::validate`, `Agent::open` | HTTPS, trust stores, estado y polling | Implementada; Windows pendiente |
| A02 | `get_hostname` L21 | `windows_platform::inventory` | `GetComputerNameExW`; errores explícitos | Implementada; Windows pendiente |
| A03 | `get_local_ip` L23 | `windows_platform::inventory` | `GetAdaptersAddresses`; IPv4/IPv6 e interfaz | Implementada; Windows pendiente |
| A04 | `get_public_ip` L32 | `observed_public_ip() -> Option<IpAddr>` | IP vista por el servidor; proxy solo si pertenece a configuración confiable | Sustituida |
| A05 | `get_mac_address` L36 | `windows_platform::inventory` | MAC opcional en adaptadores; no es identidad | Implementada; Windows pendiente |
| A06 | `get_bios_serial` L40 | `windows_platform::inventory` | WMI `Win32_BIOS` | Implementada; Windows pendiente |
| A07 | `get_wifi_info` L47 | `windows_platform::inventory` | WLAN API con liberación de buffers | Implementada; Windows pendiente |
| A08 | `get_logged_user` L57 | `windows_platform::inventory` | Sesiones interactivas WTS, no usuario SYSTEM | Implementada; Windows pendiente |
| A09 | `get_os_info` L64 | `windows_platform::inventory` | Registro Windows ProductName/build | Implementada; Windows pendiente |
| A10 | `get_uptime_hours` L66 | `windows_platform::inventory` | `GetTickCount64` en milisegundos `u64` | Implementada; Windows pendiente |
| A11 | `get_disk_free_gb` L72 | `windows_platform::inventory` | `GetDiskFreeSpaceExW`, bytes | Implementada; Windows pendiente |
| A12 | `get_ram_gb` L78 | `windows_platform::inventory` | RAM utilizable e instalada, bytes | Implementada; Windows pendiente |
| A13 | `get_security_status` L84 | `windows_platform::inventory` | WMI Defender/BitLocker sólo lectura | Implementada; Windows pendiente |
| A14 | `get_windows_location` L95 | Sin equivalente | Geolocalización retirada de inventario y acciones | Retirada |
| A15 | `capture_photo` L102 | Sin equivalente | Cámara retirada de inventario y acciones | Retirada |
| A16 | `gather_inventory` L112 | `windows_platform::inventory` | Opcionales y errores por fuente, sin cámara/ubicación rutinaria | Implementada; Windows pendiente |
| A17 | `execute_command` L126 | `Agent::execute`, `domain::validate_signed_command` | Sólo acciones tipadas, diario SQLite y lease | Implementada; Windows pendiente |
| A18 | `poll_server` L163 | `Agent::rpc` | HTTPS, mensaje y comando firmados, recibo correlacionado | Implementada; integración probada |
| A19 | `run` L191 | `Agent::run` y `agent::service` | Tokio, backoff, parada SCM, `--once` con error real | Implementada; Windows pendiente |

### Detalles de comportamiento que deben preservarse o corregirse

`capture_photo()` existe, pero `gather_inventory()` y `run()` no la llaman.
El backend acepta imágenes y recovery keys en un POST de finalización; eso no
demuestra que el agente incluido las recolecte ni las envíe automáticamente.

El parser WiFi divide BSSID por todos los caracteres `:` y toma solo el segundo
segmento; puede truncar una MAC. Además depende del idioma de `netsh`. La versión
Rust debe obtener estructuras nativas y respetar los permisos de Windows.

`GetTickCount64()` retorna 64 bits, pero el uso de `ctypes` no declara `restype`.
Existe riesgo de truncamiento del uptime al interpretarlo como `int` de 32 bits.
La corrección Rust conserva milisegundos `u64`; el panel convierte a horas.

Las cifras divididas por `1024**3` son GiB, aunque el agente las llame GB. El
protocolo nuevo guarda bytes enteros y el panel aplica la unidad. No se deben
usar ceros ni `127.0.0.1` como sustitutos silenciosos de errores de colección.

La RAM instalada y la RAM utilizable no son el mismo dato. Deben existir
`installed_bytes` y `usable_bytes`, cuando el proveedor pueda medirlas.
`GetUserNameW` devuelve la identidad del proceso y en un servicio puede ser
SYSTEM; WTS debe usarse para la identidad de las sesiones de usuario.

`execute_command()` marca `executed` sin comprobar el código de salida; el
streaming concatena salida sin límite y `full_output` no se utiliza después.
El nuevo resultado diferencia éxito, error, cancelación, truncamiento y timeout.

## 3 Equivalencias del backend PHP

Los PHP sin funciones declaradas se inventarían por flujo/handler del archivo.
La columna Rust identifica el caso de uso; en el servidor actual se expone por
`/api/v1/*` con modelos y handlers en `server/src/api.rs`.

| ID | Archivo o función actual | Equivalente Rust | Cambio de contrato | Estado |
|---|---|---|---|---|
| B01 | `login.php` | `POST /api/v1/login` | Sesión opaca, Argon2id, TOTP, cookie y CSRF; migración de hashes bcrypt no automatizada | Implementada |
| B02 | `logout.php` | `POST /api/v1/logout` | Revocación de sesión y cookie | Implementada |
| B03 | `reset_pass.php` | `POST /api/v1/password/reset` y CLI `reset-password` | Token de un uso, TOTP, sin clave fija ni recuperación pública sin control | Sustituida |
| B04 | `index.php::renderTableRows` L29 | `GET /api/v1/agents`, panel web | Datos por tenant y DOM con escape; paginación avanzada pendiente | Parcial |
| B05 | `poll.php` check-in | `POST /api/v1/agent` | Identidad Ed25519 y secuencia por agente | Implementada |
| B06 | `poll.php` selección approved | `POST /api/v1/agent` | Claim transaccional, lease y comando firmado | Implementada |
| B07 | `poll.php` update_command | `AgentOperation::Complete` | Resultado ligado a propietario y lease, estados terminales | Implementada |
| B08 | `poll.php` recovery_key | `get_encryption_status()` | Retirar recolección genérica de recovery keys; eventual escrow independiente | Sustituida |
| B09 | `poll.php` webcam_image_b64 | Sin equivalente | Captura y subida automática retiradas; no existe artefacto de cámara en esta entrega | Retirada |
| B10 | `reportar_resultado.php` | `AgentOperation::Complete` | Resultado único, acotado, en petición firmada y deduplicada | Sustituida |
| B11 | `obtener_resultado.php` | `GET /api/v1/commands` | Consulta por tenant; streaming/paginación no implementados | Parcial |
| B12 | `solicitar_accion.php` | `POST /api/v1/commands` | Operator, aislamiento y acción tipada | Implementada |
| B13 | `autorizar_accion.php` | `POST /api/v1/commands/{id}/approve` o `reject` | Aprobador distinto, TOTP, CAS y auditoría | Implementada |
| B14 | `enviar_comando.php` | `request_action()` | Unificar flujo; no inserción alternativa sin sesión | Sustituida |
| B15 | `ejecutar_directo.php` | `request_action()` | Reemplazar shell custom por operaciones diagnósticas tipadas | Sustituida |
| B16 | `iniciar_sesion_terminal.php` | Sin equivalente | Terminal arbitraria retirada; diagnóstico tipado | Retirada |
| B17 | `verificar_sesion.php` | Sin equivalente | No se emiten sesiones de terminal | Retirada |
| B18 | `totp.php::base32Decode` | `server::security` | Decodificación de biblioteca, sin parser PHP manual | Implementada |
| B19 | `totp.php::getCode` | `server::security` | TOTP RFC 6238 para provisión/verificación | Implementada |
| B20 | `totp.php::verifyCode` | `server::api::mfa` | TOTP anti-reuso y límites; WebAuthn no implementado | Implementada (TOTP) |
| B21 | `panel_seguridad.php` | `GET /api/v1/commands`, `web/app.js` | Control de rol/MFA en servidor | Implementada |

`reset_pass.php` modifica contraseñas de usuarios concretos y no muestra una
validación de sesión. Su clave fija no se reproduce en esta documentación.
`ejecutar_directo.php` inicia sesión PHP, pero no comprueba su usuario/rol y solo
mira el bit de túnel; tampoco verifica expiración en ese archivo. La consulta
del panel no convierte ese flujo en una autorización segura.

`solicitar_accion.php` intenta devolver `$lastInsertId` en una rama no POST donde
no lo define. La nueva API debe rechazar métodos inválidos con 405 y nunca
devolver éxito si no ocurrió una inserción válida.

## 4 Equivalencias de funciones JavaScript

Estas funciones son presentación. Sus controles operativos se ejecutan en Rust
en el servidor; modales, teclado y HTML permanecen en el frontend web.

| ID | Función JavaScript | Función o API Rust asociada | Comportamiento de UI |
|---|---|---|---|
| J01 | `openModal` | `get_agent_details()` | Mostrar acciones disponibles, sin construir comandos shell |
| J02 | `abrirTerminalInteractiva` | Sin equivalente | Terminal interactiva retirada |
| J03 | `esperarAprobacion` | `GET /api/v1/commands` | Mostrar estado mediante consulta del panel |
| J04 | `iniciarModoPutty` | Sin equivalente | Shell remoto retirado; sólo acciones tipadas |
| J05 | `escucharAgente` | `GET /api/v1/commands` | Resultado acotado; sin streaming ni cursor |
| J06 | `updateCommandString` | `Action` | Seleccionar tipo y parámetros; el servidor valida |
| J07 | `enviarComandoAjax` | `request_action()` | Un único flujo, tratamiento uniforme de errores |
| J08 | `abrirModalAuth` | `GET /api/v1/commands` | Mostrar acción antes de aprobar |
| J09 | `validarTotpAjax` | `POST /api/v1/commands/{id}/approve` | TOTP se valida en servidor; navegador no firma Ed25519 |
| J10 | `cancelarProtocolo` | `POST /api/v1/commands/{id}/cancel` o `reject` | Cancelación y rechazo distintos |
| J11 | `solicitarComando` | `request_action()` | Unificar panel alternativo con flujo principal |
| J12 | `abrirModal` | `GET /api/v1/commands` | Estado local del modal |
| J13 | `cerrarModal` | Sin handler Rust | Cancelar listeners y tareas locales de UI |
| J14 | `enviarAutorizacion` | `approve_action()` | Evitar doble envío; tratar conflicto de estado |

## 5 Equivalencias de datos y unidades

| Fuente SQL o campo | Modelo Rust propuesto | Regla |
|---|---|---|
| `easton_endpoints.id` | `agent_id` + `tenant_id` | Identidad enrolada y claves, no hash MAC/BIOS |
| `bios_serial`, `mac_address` | Inventario opcional | No autenticadores; pueden faltar o cambiar |
| `uptime_hours` varchar | `uptime_millis: u64` | Conversión de unidad solo en presentación |
| `disk_free_gb`, `ram_gb` float | `DiskSpace`, `MemoryInfo` con bytes `u64` | No perder precisión; diferenciar GiB y GB |
| `latitude`, `longitude` varchar | Retirado del agente Rust | No se envía ubicación |
| `last_webcam_shot` LONGBLOB | Retirado del agente Rust | No se capturan ni suben fotografías |
| `bitlocker_recovery_key` text | Retirado del inventario | Escrow especializado si se aprueba como función distinta |
| `endpoint_commands` | `CommandClaims` + registro SQL de operación | Estado, lease, nonce, firma y correlación |
| `usuarios.nivel` 1,2,3 | `Role` | Mapping explícito: lector heredado, Operator, Approver; Administrator nuevo |
| `usuarios.totp_secret` | Credencial MFA cifrada | No mezclar identidad de agente ni licencia |

La correspondencia `nivel = 1` como lector es una política de migración propuesta:
el código limita varias funciones a nivel 2/3, pero no define formalmente un rol
Auditor. Debe aprobarse el mapping al migrar cuentas. Tampoco existe actualmente
tenant_id; introducirlo implica aislamiento y migración del esquema.

## 6 Instalación y distribución

| ID | Mecanismo PowerShell actual | Equivalente Rust Windows | Estado |
|---|---|---|---|
| I01 | Comprobar administrador | Script `install_agent_rust.ps1` elevado; MSI no implementado | Implementada (script) |
| I02 | Copiar EXE a rutas del sistema/Recovery | Program Files y ProgramData con ACL | Sustituida |
| I03 | `New-Service`, inicio y parada | `windows-service` y dispatcher SCM | Implementada; Windows pendiente |
| I04 | `sc failure` | Política de recuperación SCM aún no configurada | Pendiente |
| I05 | `SetupComplete.cmd` | Sin equivalente de reinstalación oculta | Retirada |
| I06 | Registro `Run` | SCM como mecanismo de inicio visible | Retirada |
| I07 | ACL anti-borrado Everyone Deny | ACL mínimas con desinstalación administrativa posible | Sustituida |
| I08 | WMI event consumer de relanzamiento | Recuperación SCM | Retirada |
| I09 | Exclusiones Defender | Compatibilidad y firma Authenticode | Retirada |
| I10 | Forzar consentimiento de ubicación en registro | Consentimiento del usuario/política autorizada | Retirada |
| I11 | `attrib +h +s` | Archivos y servicio identificables | Retirada |
| I12 | `Stop-Service`, delete y `Stop-Process` | `uninstall_agent_rust.ps1`, parada/borrado SCM | Implementada; Windows pendiente |
| I13 | Limpieza WMI/Run/Defender heredados | Migrador de retiro explícito de la instalación antigua | Pendiente |
| I14 | Borrar `SetupComplete.cmd` completo | Retirar solo bloques propios verificados | Sustituida |
| I15 | PyInstaller `.spec` | `cargo build --release`, firma Authenticode y script; MSI no implementado | Sustituida |

Registrar un EXE Python con `New-Service` no lo convierte en servicio Windows.
El agente inspeccionado no implementa el protocolo del SCM; el nuevo binario
debe usar dispatcher, estados y handlers de parada reales. Es una observación
del código, no una prueba de ejecución del servicio antiguo.

`LockWorkStation` requiere el escritorio interactivo. El servicio usa WTS y un
proceso de sesión invocado con el token interactivo para esa acción; el camino
necesita prueba funcional y revisión de seguridad en Windows real. No debe
suponerse que una llamada directa desde Session 0 bloquea al usuario.

## 7 Funciones Rust implementadas

| ID | Función y crate | Equivalencia o capacidad | Límite de integración |
|---|---|---|---|
| R01 | `protocol::generate_signing_key` | Identidad Ed25519 nueva | Persistencia DPAPI en Windows; TPM no implementado |
| R02 | `protocol::sign_command` | Firma servidor hacia agente | Aplicada después de autorización del servidor |
| R03 | `protocol::verify_command_signature` | Autenticidad del comando | Replay y lease se comprueban en las capas servidor/agente |
| R04 | `protocol::sign_license` | Licencia firmada | Clave de propósito independiente, provisionada al iniciar |
| R05 | `protocol::verify_license_signature` | Firma de licencia | Se combina con tenant, vigencia y revocación |
| R06 | `domain::authorize_request` | Segregación de `solicitar_accion.php` | Sesión y tenant se comprueban en HTTP |
| R07 | `domain::authorize_approval` | Doble control de `autorizar_accion.php` | TOTP y auditoría integrados en API |
| R08 | `domain::transition` | Estados de `endpoint_commands` | Compare-and-set SQL en servidor |
| R09 | `domain::validate_command` | Destino, tiempo, features y parámetros | Usar después de verificar firma |
| R10 | `domain::validate_signed_command` | Unión de firma y validación operativa | Diario local reserva command_id/nonce; resultado incierto no se repite |
| R11 | `licensing::subscription_expires_at` | Cuenta 6,12,24 o meses personalizados | Política de 1 a 120 meses, fechas UTC |
| R12 | `licensing::verify_license` | Firma y estado de licencia | Revocación online se aporta desde fuente confiable |
| R13 | `licensing::license_state` | Active, GracePeriod, Expired, Revoked | No protege por sí sola contra manipulación local del reloj/archivo |
| R14 | `licensing::require_feature` | Funcionalidades y acciones offline | Gracia admite solo Inventory |
| R15 | `licensing::require_agent_capacity` | Cupo de enrolamiento | Aplicado dentro de transacción SQLite |

### Firma implementada y contrato de bytes

Se usa Ed25519 normal con `verify_strict`, sin prehash propio. La biblioteca
produce JSON UTF-8 con Serde, transporta esos bytes en `payload_b64` y firma:

```text
COMMAND: b"PUNISHELL-COMMAND-V1\0"
LICENSE: b"PUNISHELL-LICENSE-V1\0"

signed_bytes = purpose_prefix
             || key_id_length_u16_big_endian
             || key_id_ascii
             || payload_length_u32_big_endian
             || payload_utf8_bytes
```

No es JSON canónico JCS ni CBOR. El verificador comprueba los bytes exactos
recibidos antes de interpretar el JSON, por lo que proxies y consumidores no
deben reserializar el payload. `key_id` está protegido por la firma. El payload
tiene límite de 16 KiB; se rechazan campos desconocidos y acciones `custom`.
Cambiar este contrato requiere versionar el protocolo y los vectores de prueba.

Esta elección concreta el requisito anterior de representación estable. JCS o
CBOR canónico serían alternativas para interoperabilidad futura, pero requerirían
una versión distinta del protocolo y pruebas de compatibilidad.

### Activación de seis meses

El servidor emite una licencia de 6 meses y calcula la fecha
con `subscription_expires_at`. Ejemplo UTC: 11-10-2026 12:00 → 11-04-2027 12:00.
Si el día no existe, se usa el último del mes; el 31-08-2027 + 6 meses termina
el 29-02-2028. El vencimiento se aplica cuando `now >= expires_at`.

El código de activación de un uso se almacena como hash; el challenge firmado,
el cupo y la vinculación de clave pública a `agent_id` se procesan en API/SQLite.
No se ha activado una cuenta comercial real en un entorno desplegado.

La gracia offline máxima implementada es 72 horas desde el último contacto
confiable, y nunca extiende expires_at. Solo permite Inventory. No hay gracia
en un primer arranque sin contacto confiable; retroceder antes del último
contacto produce rechazo. En Windows el estado local se guarda con ACL y la
identidad privada con DPAPI; no hay TPM ni protección contra un administrador
local malicioso.

## 8 Qué se aprovecha de Lime Rust

La ruta `/home/diogenes/lime_dump_safe/analysis/lock_rust` contiene un proyecto
para hardware Linux embebido. Su organización por Cargo/daemons y los conceptos
de autenticación de mensajes sirven como referencia técnica. El BLE legacy con
nonce Ed25519 no equivale a una suscripción PuniShell de seis meses.

No se copian claves, blobs de activación ni secretos del dump. El licenciamiento
de este workspace es propio, siguiendo el contrato PuniShell; no se presenta
como implementación del servicio comercial de Lime. BLE, CAN, GPS, modem y OTA
de dispositivos son adaptadores separados de las APIs Windows.

## 9 Validación realizada y pendientes de aceptación

La suite incluye pruebas del protocolo y del dominio para firmas alteradas,
`key_id` sustituido, claves desconocidas/revocadas/expiradas, propósito,
payload acotado, acciones, roles, autoaprobación, MFA, estados, destinatario,
vigencia, meses naturales, año bisiesto, gracia, tenant, features y cupo.
También hay pruebas HTTP/SQLite de login TOTP, licencia de seis meses,
enrolamiento firmado, código de un uso, secuencia y recibo repetido.

Los controles de compilación, formato, Clippy, pruebas, documentación Cargo y
compilación cruzada de bibliotecas se registran en el README. La comparación
de rendimiento Rust/Python está pendiente: no se promete una mejora porcentual
sin benchmark comparable y medición en equipos objetivo.

Para considerar aceptado el despliegue faltan compilar la aplicación completa
con MSVC/Windows SDK, ejecutar inventario/SCM/instalación/Authenticode/rollback
en Windows real, firmar los ejecutables con un certificado controlado, probar
rotación y recuperación ante caída, configurar copias de seguridad y monitoreo,
y decidir si se requiere MSI. La referencia Linux sólo demuestra los flujos
del núcleo y HTTP; la comprobación cruzada de `windows-platform` no prueba
comportamiento nativo.

## 10 Referencias primarias

- Verificación Ed25519 utilizada: https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html
- Meses naturales: https://docs.rs/chrono/0.4.45/chrono/struct.DateTime.html#method.checked_add_months
- Uptime de 64 bits: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64
- RAM utilizable: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex
- RAM instalada: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getphysicallyinstalledsystemmemory
- Sesiones Windows: https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw
- Adaptadores de red: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
- WiFi: https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanqueryinterface
- Escritorio interactivo para bloqueo: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-lockworkstation
- Protección local DPAPI: https://learn.microsoft.com/en-us/windows/win32/SecCrypto/example-c-program-using-cryptprotectdata
