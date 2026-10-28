# Informe maestro: PuniShell, Lime Rust y nueva plataforma segura

**Fecha:** 7 de octubre de 2026  
**Alcance:** inventario, hallazgos, firmas, riesgos y arquitectura futura Rust.

## 1. Objetivo y método

Se revisaron dos ubicaciones:

1. PuniShell MDM: /home/diogenes/Desktop/PuniShell_Proyect-main
2. Lime Rust: /home/diogenes/lime_dump_safe/analysis/lock_rust

La revisión fue estática y de solo lectura. Se inspeccionaron archivos, PHP,
Python, PowerShell, SQL, Cargo, documentación, formatos binarios, hashes,
cabeceras ELF y referencias a autenticación y actualización. No se ejecutaron
agentes, instaladores, comandos remotos ni actualizaciones de hardware.

## 2. Cómo se encontró el código

### 2.1 PuniShell

La estructura principal encontrada fue:

    agente_python/agente_punishell.py
    backend_php/
    BBDD_Pruebas/punishell_db.sql
    despliegue_ps1/
    agente_punishell.spec
    build/
    dist/agente_punishell.exe
    readme.txt

El flujo se reconstruyó leyendo el agente, endpoints PHP, JavaScript, SQL,
instalador, desinstalador y configuración PyInstaller.

### 2.2 Lime Rust

La estructura principal encontrada fue:

    Cargo.toml
    crates/lime-lockd
    crates/lime-bled
    crates/lime-gpsd
    crates/lime-ipc
    crates/lime-modemd
    crates/lime-otad
    crates/uart_spy
    firmware/
    docs/
    embedded/
    tools/
    limebike-lock.orig.20260716032907

Este proyecto es una reimplementación Rust para hardware/firmware de Lime,
distinta de PuniShell. Aporta evidencia sobre comunicación, autenticación y
actualización, pero no debe copiarse sin validar derechos y seguridad.

## 3. Inventario numerado de PuniShell

### 3.1 Agente

1. Obtiene hostname, IP local, IP pública y MAC.
2. Consulta serial BIOS, SSID, BSSID y usuario conectado.
3. Consulta sistema operativo, uptime, RAM y disco.
4. Consulta BitLocker y Microsoft Defender.
5. Consulta geolocalización.
6. Contiene una función de captura webcam JPEG/Base64, sin llamada desde el inventario ni el bucle principal.
7. Envía inventario a poll.php.
8. Recibe comandos aprobados.
9. Cambia el polling de 10 a 1 segundo para terminal.
10. Ejecuta cadenas con subprocess y shell=True.
11. Modifica parcialmente ping infinito.
12. Transmite la salida línea a línea.
13. Marca comandos como ejecutados.
14. Repite el ciclo indefinidamente.

### 3.2 Backend y panel

15. Autentica usuarios con sesiones PHP y password_verify.
16. Implementa niveles 1, 2 y 3.
17. Muestra inventario, red, usuario, RAM y sistema.
18. Muestra ubicación y última imagen de webcam.
19. Permite solicitar acciones.
20. Permite aprobar o rechazar acciones.
21. Implementa TOTP de seis dígitos.
22. Contiene el bypass de desarrollo 000000.
23. Abre terminal durante un periodo limitado.
24. Encola acciones con estados pending, approved, executed, failed y rejected.
25. Entrega comandos aprobados al agente.
26. Recibe y almacena resultados.
27. Guarda posibles llaves BitLocker.
28. Guarda imágenes como LONGBLOB.

### 3.3 Instalación

29. Registra un servicio Windows.
30. Configura recuperación automática.
31. Crea SetupComplete, Run y WMI relanzador.
32. Modifica ACL para dificultar el borrado.
33. Agrega exclusiones de Defender.
34. Oculta carpetas instaladas.
35. Activa el servicio de ubicación.
36. Incluye un desinstalador para retirar esas capas.

## 4. Inventario numerado de Lime Rust

37. lime-lockd concentra lock, CAN/SLCAN y periféricos.
38. lime-bled implementa el daemon BLE.
39. lime-gpsd cubre GPS.
40. lime-ipc implementa IPC.
41. lime-modemd cubre modem.
42. lime-otad cubre actualización OTA.
43. uart_spy contiene herramientas UART.
44. El workspace usa Cargo y Rust 2021.
45. Usa Tokio, Serde, JSON y libc.
46. Incluye adaptadores Linux, CANopen y documentación de hardware.
47. Documenta HMAC para el flujo BLE moderno.
48. Documenta firma Ed25519 de nonce en el flujo BLE legacy.
49. Esa firma autentica mensajes/sesiones, no el archivo ELF.
50. El OTA documentado usa MD5 de manifiesto y comparación de bytes.
51. No se encontró validación criptográfica del BIN antes de escribirlo.

## 5. Evidencia del archivo original

Archivo:

    /home/diogenes/lime_dump_safe/analysis/lock_rust/limebike-lock.orig.20260716032907

Características:

- ELF 32-bit ARM EABI5.
- Linux embebido.
- Cargador /lib/ld-linux.so.3.
- No stripped.
- GNU Build ID: ab5c731b89124fb9826f98b2d234b6f835d5a477.
- SHA-256: cb132ade3f21a9ecf53f6383c153fb65f0d0751b8e0c20001de8a3ca605f33f6.

No es un PE de Windows y no tiene firma Authenticode.

Librería vendor:

- libfw.so.1.0.0.
- Build ID: 4b9be131ca87ed62558056071a5ca47f91e701d2.
- SHA-256: 1af41d86dd53536c030b614e0f8b7301af3cc2e14b6823c7fe8340771d779337.

Firmware BLE:

- SHA-256: 8832e2bd7137eb723a2a2b1307b54a86db17db25f369f6ed2cf33d43310bbc6a.

El ejecutable PuniShell es un PE generado por PyInstaller, pero el repositorio
no demuestra que tenga una firma Authenticode válida.

## 6. Fallas verificadas

### 6.1 Críticas

52. El agente no tiene identidad criptográfica propia.
53. El check-in no está firmado por dispositivo.
54. Los resultados pueden falsificarse o inyectarse.
55. El servidor no firma comandos Ed25519 para verificación en el agente.
56. Se ejecutan cadenas arbitrarias con shell=True.
57. No hay allowlist, sandbox ni límites robustos de proceso.
58. El transporte documentado usa HTTP.
59. Existe bypass TOTP 000000.
60. El dump incluye datos sensibles y semilla TOTP.
61. Se usa root de MySQL sin contraseña.
62. Cámara, ubicación y BitLocker carecen de consentimiento y retención sólidos.
63. El instalador crea persistencia oculta y modifica Defender.
64. No hay separación fuerte entre licencia, identidad y autorización.

### 6.2 Altas

65. Falta CSRF, rate limiting y bloqueo ante intentos TOTP repetidos.
66. Las sesiones no están endurecidas de forma uniforme.
67. Falta includes/SimpleTOTP.php, aunque se intenta cargar.
68. Un flujo de denegación tiene el exit comentado.
69. Se mezclan mysqli y PDO.
70. Se repiten credenciales en varios PHP.
71. backend_php/esquema.sql está vacío.
72. El esquema y el código presentan deriva.
73. No hay lease transaccional para reclamar un comando.
74. Puede haber ejecución duplicada.
75. executed_at no se actualiza de forma coherente.
76. La salida e imágenes no tienen límites y retención definidos.
77. El escape HTML no es uniforme.
78. Se exponen errores SQL.
79. No existe cadena reproducible de compilación y firma.

La persistencia oculta, WMI relanzador, exclusiones Defender y ACL anti-borrado
no deben migrarse a Rust. La nueva versión debe usar un servicio visible,
firmado y desinstalable.

## 7. Nueva arquitectura Rust

    punishell-rust/
    ├── crates/protocol
    ├── crates/domain
    ├── crates/agent
    ├── crates/server
    ├── crates/persistence
    ├── crates/licensing
    ├── crates/access-control
    ├── crates/agent-identity
    ├── crates/windows-platform
    ├── crates/update
    └── crates/test-support

El agente genera una clave propia, se enrola, verifica licencia, envía
heartbeat firmado, valida comandos, ejecuta acciones tipadas y firma resultados.
El servidor gestiona tenants, usuarios, dispositivos, licencias, leases,
auditoría y claves de firma.

Acciones iniciales:

- collect_inventory;
- lock_workstation;
- diagnostic_bundle limitado;
- restart_managed_service;
- request_update;
- rotate_agent_key;
- disable_agent.

No se debe usar shell libre como contrato principal.

## 8. Firma para cada parte

### 8.1 Ejecutables e instaladores

Firmar con Authenticode el agente EXE, DLLs y MSI/MSIX. La clave privada debe
estar en Azure Artifact Signing, HSM o servicio seguro de CI, nunca en Git ni
dentro del agente.

### 8.2 Comandos servidor → agente

Firmar cada comando con Ed25519 del servidor. El sobre debe incluir:

    protocol_version
    key_id
    command_id
    tenant_id
    agent_id
    action_type
    parameters
    issued_at
    expires_at
    nonce
    signature

El agente rechaza firmas inválidas, claves revocadas, agentes incorrectos,
comandos expirados, nonces repetidos, command_id repetidos, funcionalidades no
licenciadas y parámetros fuera de política.

Debe firmarse una representación estable definida por contrato. El código Rust
actual transporta y verifica bytes JSON exactos dentro de un sobre versionado
(sección 15), sin reserializarlos. CBOR canónico o JCS son alternativas para una
versión distinta del protocolo, no formatos intercambiables con el actual.
HTTPS sigue siendo necesario porque Ed25519 autentica, pero no cifra.

### 8.3 Agente → servidor

Cada agente firma heartbeat, inventario, claim, inicio, resultado y error con
su propia clave Ed25519.

### 8.4 Licencias

Firmar con Ed25519 los tokens de licencia. Incluir license_id, tenant_id, plan,
features, max_agents, issued_at, expires_at, offline_grace_hours y key_id.

### 8.5 Actualizaciones

Usar SHA-256 para integridad, Ed25519 para el manifiesto y Authenticode para el
ejecutable. Verificar manifiesto, hash, firma y editor antes de instalar.

### 8.6 Firmware

Si se mantiene firmware, usar una clave separada, firma de imagen, SHA-256,
versión, hardware objetivo, contador anti-rollback, verificación previa,
verificación posterior y rollback. MD5 no debe ser el control principal.

### 8.7 Aprobación humana

TOTP es segundo factor, no firma de comando. Para acciones críticas se requiere
solicitud de operador, aprobación MFA de jefatura, registro de aprobación y
firma del comando final por el servidor. WebAuthn es preferible para una
aserción resistente a phishing.

## 9. Control de acceso y activación

Roles:

- Administrador: tenants, usuarios, licencias y políticas.
- Operador: inventario y solicitudes.
- Jefatura: aprobación de acciones sensibles.
- Auditor: lectura y auditoría.
- Agente: identidad propia y acciones autorizadas.

Planes:

- starter_6m;
- business_12m;
- enterprise_24m;
- custom.

Flujo de activación:

1. Crear tenant.
2. Seleccionar plan, cupo y funcionalidades.
3. Emitir licencia firmada.
4. Generar código de un solo uso.
5. Guardar el código hasheado y con vencimiento corto.
6. El instalador solicita el código.
7. El agente genera su clave.
8. El servidor vincula agente, tenant y licencia.
9. Entrega licencia firmada y token corto.
10. El agente protege el material local con DPAPI/CNG/TPM.
11. Comienza el heartbeat firmado.

La vigencia de seis meses se calcula en servidor. La gracia offline debe ser
limitada, por ejemplo 72 horas, y no habilitar acciones críticas indefinidas.

## 10. APIs nativas Windows

La capa windows-platform debe encapsular:

- GetComputerNameExW: hostname.
- GetAdaptersAddresses: red y adaptadores.
- GetDiskFreeSpaceExW: disco.
- GetPhysicallyInstalledSystemMemory: RAM.
- GetTickCount64: uptime.
- GetUserNameW o WTSQuerySessionInformationW: usuario.
- Service Control Manager: servicio.
- CryptProtectData y CryptUnprotectData: secretos locales.
- Media Foundation/Windows Media Capture: cámara con consentimiento.
- Windows Location API: ubicación con consentimiento.
- Proveedor Windows/WMI: BitLocker bajo política.
- WinHTTP o cliente Rust TLS: red.

El código unsafe debe estar aislado en windows-platform.

## 11. Mejoras

80. Eliminar Python y PyInstaller del agente.
81. Usar Tokio para red y temporizadores.
82. Reutilizar conexiones HTTPS.
83. Aplicar backoff adaptativo.
84. Evitar PowerShell para cada dato.
85. Limitar y comprimir salida.
86. Procesar inventario sensible bajo demanda.
87. Usar colas con lease e idempotencia.
88. Medir memoria, CPU, latencia y red antes y después.
89. Mantener servicio visible y compatible con Defender.
90. Aplicar consentimiento, retención y auditoría.

## 12. Plan de migración

### Fase 0: contención

- retirar 000000;
- rotar contraseñas, TOTP y secretos;
- aislar instalador actual;
- retirar persistencia evasiva;
- sanear el dump.

### Fase 1: contratos

- definir mensajes, acciones, estados, leases, licencias, claves y auditoría.

### Fase 2: seguridad base

- enrolamiento, identidad Ed25519, firma de comandos, HTTPS y RBAC.

### Fase 3: agente Rust

- servicio visible, inventario, heartbeat, licencia y acciones seguras.

### Fase 4: servidor Rust

- API, migraciones, colas, auditoría y portal de activación.

### Fase 5: distribución

- pipeline reproducible, Authenticode, manifiestos firmados, MSI/MSIX y hashes.

### Fase 6: retirada

- migrar dashboard, apagar PHP, retirar Python y eliminar scripts anteriores.

## 13. Criterios de aceptación

1. Un agente no enrolado no recibe comandos.
2. Un comando alterado no valida.
3. Un comando repetido no se ejecuta dos veces.
4. Un comando expirado se rechaza.
5. Una licencia de seis meses vence en servidor y agente.
6. Una licencia revocada bloquea funciones administrativas.
7. Las claves privadas del servidor y de licenciamiento nunca aparecen en el agente; su propia clave de identidad se guarda protegida localmente.
8. El ejecutable e instalador son verificables.
9. Una actualización sin hash o firma correcta no se instala.
10. No existe shell arbitrario como API principal.
11. Cada operación sensible queda auditada.
12. Cámara, ubicación y BitLocker están desactivados por defecto.
13. La pérdida de red no causa ejecución insegura.
14. Existen pruebas de firma, replay, expiración, revocación, roles y rollback.

## 14. Conclusión

PuniShell es un prototipo funcional de administración remota, pero mezcla
telemetría sensible, ejecución de comandos y persistencia invasiva con controles
insuficientes.

Lime Rust aporta una base distinta para hardware y firmware. El binario original
es ELF ARM con Build ID y hashes, no un PE firmado de Windows. Sus documentos
muestran HMAC, firma Ed25519 de mensajes y un OTA que debe evolucionar de MD5 a
firma criptográfica.

La nueva plataforma debe usar Authenticode para software, Ed25519 para comandos,
licencias y respuestas, una clave separada para firmware, SHA-256 para
integridad, TLS para confidencialidad, RBAC/MFA para personas y auditoría para
cada acción.

## 15. Correspondencia funcional e implementación del 11 de octubre de 2026

El workspace `punishell-rust` contiene seis crates: `protocol`, `domain`,
`licensing`, `server`, `agent` y `windows-platform`. El servidor HTTPS y el
agente se compilan y prueban en Linux; la capa Win32 se comprueba para el target
Windows, pero aún no se ha ejecutado ni firmado el paquete en Windows real.
El estado detallado por función se encuentra en
[`EQUIVALENCIAS_FUNCIONES_RUST.md`](punishell-rust/docs/EQUIVALENCIAS_FUNCIONES_RUST.md)
y la forma de compilar y validar en [`README.md`](punishell-rust/README.md).

La correspondencia cubre las 19 funciones Python, 21 flujos PHP, 14 funciones
JavaScript, campos SQL, 15 mecanismos de instalación y 15 funciones del núcleo
Rust. Distingue implementación, validación Windows pendiente, sustitución de
comportamiento y retirada de mecanismos invasivos.

El código implementa firma/verificación Ed25519, identidad protegida con DPAPI
en Windows, meses naturales, revocación, gracia offline, cupos, roles, doble
control TOTP, acciones tipadas, diario y recibos de agente, activación de un uso,
HTTPS/SQLite, inventario Win32 y actualización con manifiesto firmado,
SHA-256 y Authenticode. Las pruebas unitarias e integradas Linux cubren esos
contratos principales, pero no sustituyen pruebas end-to-end Windows.

La representación firmada implementada transmite los bytes JSON exactos en
base64url y firma un prefijo de propósito más key_id y payload con longitudes.
No es JCS ni CBOR canónico: no se debe reserializar el payload antes de verificar.
El agente y el servidor actuales usan este contrato; cambiarlo requiere una
versión explícita y pruebas de compatibilidad.

Las reservas persistentes de secuencia, nonce y `command_id`, leases, sesiones,
MFA, scripts de instalación, inventario y actualizaciones ya tienen código.
Quedan pendientes la compilación y prueba completas en Windows con SDK,
certificado de firma real, evaluación de despliegue/rollback, endurecimiento
operativo, benchmarks comparables y aceptación de seguridad. La firma por sí
sola no impide replay; un lease tampoco prueba ejecución física exactamente
una vez ante pérdida de confirmación.
