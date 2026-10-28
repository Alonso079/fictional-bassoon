# Informe técnico de PuniShell MDM

**Fecha de revisión:** 7 de octubre de 2026  
**Alcance:** repositorio actual, agente Windows, backend PHP/MySQL, scripts PowerShell, esquema y dump de base de datos.

## 1. Resumen ejecutivo

PuniShell es un prototipo de administración remota de equipos Windows. Su flujo principal es:

1. Un agente Python recopila inventario y hace *check-in* periódico.
2. El backend PHP registra el equipo y entrega comandos autorizados.
3. Un operador crea solicitudes y una jefatura las aprueba mediante TOTP.
4. El agente ejecuta el comando, transmite la salida y marca el resultado.
5. Existe un modo de terminal interactiva que reduce el intervalo de consulta a un segundo durante una sesión.

La idea funcional es reconocible, pero la implementación actual presenta riesgos críticos: transporte sin TLS, endpoints del agente sin autenticación criptográfica, ejecución arbitraria mediante `shell=True`, credenciales de base de datos por defecto, bypass TOTP `000000`, secretos y datos sensibles en el dump SQL, ausencia de controles CSRF/rate limiting y persistencia deliberadamente oculta con exclusiones de Defender, Registro, WMI y `SetupComplete`.

**Conclusión:** no se recomienda desplegar esta versión en producción ni trasladar literalmente sus mecanismos de ocultamiento. La migración a Rust debe ser una reconstrucción segura del dominio MDM, no una conversión línea por línea.

## 2. Estructura actual

```text
PuniShell_Proyect-main/
├── agente_python/agente_punishell.py       Agente Windows en Python
├── backend_php/                            Dashboard y API PHP
│   ├── index.php                            Inventario y acciones
│   ├── login.php/logout.php                 Sesión web
│   ├── poll.php                             Check-in y entrega de comandos
│   ├── solicitar_accion.php                 Solicitud nivel operador
│   ├── autorizar_accion.php                 Aprobación nivel jefatura + TOTP
│   ├── iniciar_sesion_terminal.php          Apertura de terminal interactiva
│   ├── ejecutar_directo.php                 Encolado de comandos interactivos
│   ├── reportar_resultado.php               Streaming de salida
│   ├── obtener_resultado.php                Lectura de salida
│   ├── verificar_sesion.php                 Expiración del túnel
│   └── includes/                            Plantillas y JavaScript
├── BBDD_Pruebas/punishell_db.sql            Dump de esquema y datos de prueba
├── despliegue_ps1/install_agent.ps1         Instalación y persistencia
├── despliegue_ps1/uninstall_punishell.ps1  Desinstalación
├── agente_punishell.spec                    Configuración PyInstaller
├── build/                                   Artefactos de compilación
├── dist/                                    Ejecutable generado
└── readme.txt                               Manual de despliegue
```

Observaciones de estructura:

- `backend_php/esquema.sql` está vacío; el único esquema útil está dentro del dump de `BBDD_Pruebas`.
- El backend mezcla `mysqli` y PDO, repite credenciales y conexión a la base de datos y no tiene una capa de configuración común.
- No hay `Cargo.toml`, pruebas automatizadas, migraciones versionadas, archivo de configuración seguro ni pipeline reproducible.
- `iniciar_sesion_terminal.php` requiere `includes/SimpleTOTP.php`, pero ese archivo no existe; la clase real está en `backend_php/totp.php`.
- El repositorio incluye binarios generados y un dump con datos operativos/sensibles; debe tratarse como material comprometido hasta hacer una rotación.

## 3. Funcionamiento actual

### 3.1 Agente

`agente_python/agente_punishell.py` realiza lo siguiente:

- Obtiene hostname, IP local/pública, MAC, serial BIOS, SSID/BSSID, usuario, sistema operativo, uptime, disco, RAM, estado BitLocker y Defender.
- Intenta obtener ubicación de Windows mediante `GeoCoordinateWatcher`.
- Contiene captura de webcam en JPEG/Base64, aunque `gather_inventory()` no la dispara por sí mismo.
- Hace POST JSON a `backend_php/poll.php` cada 10 segundos.
- Cambia a un intervalo de un segundo cuando el servidor devuelve `terminal_live = 1`.
- Ejecuta los comandos devueltos y envía cada línea a `reportar_resultado.php`.
- Marca el comando como `executed` al terminar.

### 3.2 Backend y dashboard

- `login.php` valida el hash de contraseña con `password_verify()` y guarda `user_id`, `username` y `nivel` en sesión.
- Nivel 2 solicita acciones; nivel 3 aprueba o rechaza.
- `autorizar_accion.php` verifica TOTP y cambia el estado a `approved`; para `open_tunnel` activa el terminal por 30 minutos.
- `poll.php` identifica equipos principalmente por `mac_address` y `bios_serial`, actualiza inventario y devuelve comandos aprobados.
- `ejecutar_directo.php` encola comandos interactivos si el indicador de terminal está activo.
- El frontend consulta periódicamente los resultados y muestra el inventario, GPS, webcam y estados de seguridad.

### 3.3 Modelo de datos

El dump define tres tablas principales:

| Tabla | Función | Riesgo principal |
|---|---|---|
| `easton_endpoints` | Inventario, ubicación, webcam, BitLocker y estado de terminal | Datos sensibles concentrados y varios campos sin normalización |
| `endpoint_commands` | Cola, aprobación, ejecución y salida | Permite almacenar comandos/salidas arbitrarias y no tiene auditoría completa |
| `usuarios` | Usuarios, rol y secreto TOTP | Secreto TOTP almacenado directamente y datos de prueba incluidos |

Estados observados: `pending`, `approved`, `executed`, `failed` y `rejected`.

## 4. Fortalezas actuales

- Existe una separación inicial entre operador y jefatura (*maker-checker*).
- Se utilizan consultas preparadas en varios puntos importantes.
- Las contraseñas se almacenan con hash bcrypt en el dump.
- Existe expiración de sesión de terminal en el modelo de datos.
- El agente maneja fallos de varias fuentes de inventario sin detener todo el proceso.
- Hay un desinstalador que intenta retirar cada mecanismo instalado.
- El flujo de comandos deja estados y salida, lo que permite reconstruir parcialmente una operación.

Estas fortalezas son de diseño o prototipo; no compensan los problemas de autenticidad del agente, transporte, control de comandos y persistencia.

## 5. Debilidades y riesgos priorizados

### Críticos — corregir antes de cualquier despliegue

1. **Autenticación del agente insuficiente.** `poll.php`, `reportar_resultado.php` y otros endpoints no exigen un token por equipo ni una firma de mensaje. Un tercero que alcance el servidor podría falsificar inventario, inyectar estados, subir resultados o asociar datos a otro equipo.
2. **Ejecución arbitraria.** `subprocess.Popen(..., shell=True)` acepta una cadena completa del servidor. No existe lista de acciones permitidas, sandbox, límite de tiempo, límite de salida ni cancelación segura.
3. **Transporte no cifrado.** El manual y el agente usan `http://`; inventario, comandos, ubicación, webcam y posibles llaves BitLocker viajan sin TLS.
4. **Bypass de autenticación.** `000000` libera terminal o aprobación en código de producción. Debe eliminarse, no ocultarse.
5. **Persistencia y evasión defensiva.** El instalador agrega exclusiones de Defender, rutas ocultas, `Run`, `SetupComplete`, WMI y ACL que impide borrar. Esto es indistinguible de patrones de malware y rompe el principio de administración transparente.
6. **Secretos comprometidos.** El dump contiene una semilla TOTP y usuarios de prueba. Las credenciales, semillas y tokens deben rotarse y el dump debe sanitizarse.

### Altos

- Usuario de base de datos `root` sin contraseña, repetido en múltiples archivos.
- Sin CSRF, rate limiting, política de bloqueo de cuenta ni endurecimiento de cookies de sesión.
- `iniciar_sesion_terminal.php` no termina la ejecución después de una denegación de sesión y referencia un archivo inexistente.
- `enviar_comando.php` no aplica sesión/rol visible y `obtener_resultado.php` no valida que el solicitante pueda leer el comando.
- `verificar_sesion.php` construye SQL con interpolación de un ID, aunque hoy lo convierta a entero.
- Los endpoints devuelven mensajes de error SQL y detalles de conexión.
- El estado de finalización y `executed_at` no se actualizan de forma consistente; existen parches de compatibilidad para columnas que no están en el esquema.
- No hay transacción ni bloqueo para reclamar un comando; dos check-ins podrían ejecutar la misma orden.
- No hay timeout de proceso; un comando puede bloquear el agente indefinidamente.
- La salida se concatena sin límite y la webcam/Base64 se almacena sin validación de tamaño o retención.
- El dashboard imprime campos de inventario sin escape uniforme y mezcla HTML construido con datos de equipos.

### Medios y bajos

- Dependencia externa de `api.ipify.org` para IP pública.
- Dependencia de PowerShell, WMI y herramientas del sistema con cambios entre versiones de Windows.
- Sin configuración por entorno; las URLs están hardcodeadas.
- Sin pruebas unitarias, de integración, de contrato ni de recuperación.
- Sin versionado de esquema; `backend_php/esquema.sql` vacío y dump con datos reales/de prueba mezclados.
- Artefactos `build/` y `dist/` dificultan reproducibilidad y pueden contener código o datos que ya no corresponden a la fuente.

## 6. Áreas de mejora funcional

### Seguridad y control

- Migrar a HTTPS obligatorio y validar certificados.
- Registrar cada agente con identidad única, clave privada local y firma Ed25519 de cada solicitud.
- Sustituir el shell libre por acciones tipadas: `collect_inventory`, `lock_workstation`, `restart_service`, `capture_diagnostic` y otras aprobadas expresamente.
- Mantener comandos sensibles detrás de aprobación explícita, expiración, doble control y auditoría inmutable.
- Eliminar cámara, ubicación y recuperación BitLocker por defecto; habilitarlas solo con consentimiento, política, motivo y retención definida.
- Guardar la llave de recuperación cifrada o, preferentemente, no almacenarla en el MDM.

### Calidad y operación

- Centralizar configuración y secretos mediante variables de entorno/secret manager.
- Crear migraciones versionadas y una base limpia de desarrollo sin datos personales.
- Añadir health checks, métricas de check-in, colas, reintentos con backoff y alarmas de agente fuera de línea.
- Definir retención y borrado de comandos, resultados, imágenes y telemetría.
- Separar API, dominio, persistencia y frontend.
- Incorporar pruebas de contrato entre agente y servidor, pruebas de expiración y pruebas de autorización por rol.

## 7. Sistema de activación y referencia a Lime Lock

### Estado encontrado

No hay archivos ni referencias a `Lime Lock` en el repositorio revisado. Por lo tanto, no es posible afirmar qué código, API, licencia o reglas exactas se “sacaron” de ese sistema. Lo que sí existe y debe considerarse parte del mecanismo actual de autorización es:

- TOTP de 6 dígitos en `backend_php/totp.php`.
- Aprobación de acciones por nivel 3.
- Apertura de terminal por 30 minutos.
- Bypass fijo `000000` en `autorizar_accion.php` e `iniciar_sesion_terminal.php`.

El bypass no es un sistema de activación válido y debe eliminarse en la primera fase de seguridad.

### Diseño recomendado de activación para la versión Rust

La activación debe ser un módulo de licenciamiento separado del permiso operativo de ejecutar acciones:

```text
Servidor de licencias
        │  licencia firmada + límites + características
        ▼
API de PuniShell ── revocación / cupos / auditoría
        │
        ▼
Agente Rust ── verifica firma con clave pública embebida
```

Formato lógico de licencia, sin secretos del servidor:

```json
{
  "license_id": "uuid",
  "tenant_id": "uuid",
  "product": "punishell-mdm",
  "features": ["inventory", "lock_workstation"],
  "max_endpoints": 25,
  "issued_at": "RFC-3339",
  "expires_at": "RFC-3339",
  "device_binding": "enrollment-id",
  "key_id": "licensing-key-01",
  "signature": "base64url"
}
```

Reglas obligatorias:

1. La clave privada de firma vive únicamente en el servidor de licencias.
2. El agente solo contiene la clave pública y verifica firma, producto, tenant, vigencia, características y vínculo de enrolamiento.
3. El vínculo no debe depender solo de MAC o BIOS; debe usar un `enrollment_id` y una clave generada por el agente.
4. Debe existir activación online, desactivación, revocación, renovación y una gracia offline limitada y configurable.
5. El token local debe guardarse protegido por DPAPI/Credential Manager en Windows, nunca en texto plano ni dentro del ejecutable.
6. El servidor debe controlar cupos, sesiones, dispositivos revocados y auditoría.
7. Si Lime Lock es una dependencia legítima, se debe integrar detrás de una interfaz `ActivationProvider`, conservar solo su contrato documentado y verificar licencia/derechos antes de copiar código o claves.

Este diseño no intenta reproducir un componente propietario no presente en el repositorio; deja una frontera técnica para incorporarlo de forma legal y testeable cuando se disponga de su documentación.

## 8. Migración completa a Rust

### Arquitectura objetivo

```text
punishell/
├── Cargo.toml                 workspace
├── crates/protocol/           DTOs, versiones y validación de mensajes
├── crates/domain/             estados, permisos, políticas y casos de uso
├── crates/agent/              agente Windows
├── crates/server/             API HTTP, autenticación y autorización
├── crates/persistence/        SQLx y migraciones
├── crates/licensing/          licencia firmada y activación
├── crates/windows-platform/   inventario y acciones Windows permitidas
└── migrations/                esquema versionado
```

### Componentes sugeridos

- API: `axum` + `tokio` + `tower`.
- Serialización: `serde` y `serde_json`.
- Persistencia MariaDB/MySQL: `sqlx` con migraciones.
- HTTP del agente: `reqwest` con TLS nativo.
- Observabilidad: `tracing` y `tracing-subscriber`.
- Contraseñas: `argon2`.
- TOTP temporal, si se mantiene: crate mantenida y pruebas de vectores RFC; sin bypass.
- Firma de licencias y mensajes: `ed25519-dalek` o una biblioteca criptográfica auditada.
- Servicio Windows: `windows-service`; APIs nativas con `windows`.
- Inventario: APIs Windows tipadas y `sysinfo`, evitando depender de PowerShell para cada dato.

### Protocolo nuevo

Cada mensaje debe incluir `protocol_version`, `agent_id`, `request_id`, `timestamp`, `nonce`, tipo de operación y firma. El servidor debe rechazar mensajes repetidos, atrasados o con firma inválida. Los comandos deben tener estado transaccional:

```text
pending → approved → claimed → running → succeeded|failed|expired|cancelled
```

El agente debe reclamar un comando con un lease, ejecutar solo acciones permitidas, aplicar timeout, limitar salida y confirmar el resultado con `request_id`.

### Estrategia de migración sin caída

1. **Fase 0 — Contención:** retirar `000000`, rotar contraseñas/semillas, sacar datos personales del dump, desactivar persistencia oculta y exigir una red aislada.
2. **Fase 1 — Contrato:** congelar DTOs, estados, roles, reglas de aprobación y esquema nuevo; documentar qué funciones se eliminan por riesgo.
3. **Fase 2 — Servidor Rust:** implementar API de check-in, enrolamiento, autenticación del agente, cola idempotente y auditoría. Mantener el dashboard PHP como cliente temporal.
4. **Fase 3 — Agente Rust:** portar inventario, check-in, verificación de licencia y acciones tipadas. Instalar como servicio visible, firmado y desinstalable, sin WMI/Run/SetupComplete ni exclusiones de Defender.
5. **Fase 4 — Activación:** desplegar el servicio de licencias, activar dispositivos de prueba, verificar renovación/revocación/offline y migrar licencias válidas.
6. **Fase 5 — Frontend y retirada:** pasar el dashboard a la API Rust, migrar datos sanitizados, apagar endpoints PHP y retirar el agente Python después de una ventana de convivencia controlada.

### Criterios de aceptación

- Un agente no registrado no puede enviar inventario ni recibir comandos.
- La repetición de una solicitud no duplica la ejecución.
- Ningún comando arbitrario llega al sistema operativo sin pasar una política explícita.
- La licencia inválida, vencida o revocada bloquea solo las capacidades licenciadas y deja un estado auditable.
- La sesión de terminal caduca en servidor y agente.
- Todos los datos sensibles tienen cifrado, retención y autorización verificables.
- El instalador es visible, firmado, reversible y detectado como software empresarial legítimo.
- Existen pruebas automatizadas de autorización, protocolo, expiración, revocación, errores de red y migración.

## 9. Plan inmediato recomendado

1. No ejecutar el instalador PowerShell fuera de un laboratorio aislado.
2. Rotar las credenciales de usuarios, la semilla TOTP y cualquier secreto utilizado en el dump.
3. Retirar `BBDD_Pruebas/punishell_db.sql` del flujo de producción y generar un dump anonimizado.
4. Eliminar el bypass `000000`, el shell libre y los endpoints sin autenticación antes de una prueba multi-equipo.
5. Completar `backend_php/esquema.sql` mediante migraciones reales o congelar el esquema del dump en una versión limpia.
6. Implementar primero la identidad criptográfica del agente y el protocolo firmado; después portar funcionalidades.
7. Aportar el contrato o código autorizado de Lime Lock si se necesita una integración exacta; no se encontró evidencia suficiente en este repositorio para documentarla como existente.

## 10. Validaciones realizadas

- `python3 -m py_compile agente_python/agente_punishell.py` → correcto.
- Se revisaron todos los PHP, scripts PowerShell, el agente, el `.spec`, el dump SQL y los artefactos de compilación.
- No fue posible ejecutar `php -l` porque PHP no está instalado en el entorno de revisión.
- No se encontró un repositorio Git operativo en `.git`; no se pudo comparar historial ni identificar el origen de Lime Lock.

