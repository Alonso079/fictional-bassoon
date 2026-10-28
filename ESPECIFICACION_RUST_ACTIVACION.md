# Especificación de arquitectura Rust y activación de PuniShell

**Estado:** diseño técnico con bibliotecas protocol, domain y licensing implementadas desde el 11 de octubre de 2026; integración Windows y servidor pendiente.  
**Objetivo:** reemplazar el agente Python y el backend PHP por una plataforma Rust segura, rápida, auditable y con activación por suscripción.

## 1. Separar tres conceptos

No deben confundirse:

1. **Firma de Windows:** demuestra que el ejecutable fue publicado por Easton/PuniShell y ayuda a validar su integridad.
2. **Activación de licencia:** determina si el tenant, la instalación y las funcionalidades están habilitados durante 6, 12 o más meses.
3. **Autorización operativa:** determina qué usuario puede ver un equipo o ejecutar una acción concreta.

Una aplicación puede estar correctamente firmada y aun así tener la licencia vencida. También puede tener licencia válida pero negar una acción a un operador sin permisos.

## 2. Estructura del workspace Rust

```text
punishell-rust/
├── Cargo.toml
├── crates/
│   ├── protocol/              Mensajes versionados y validación
│   ├── domain/                Entidades, estados, permisos y casos de uso
│   ├── agent/                 Binario del servicio Windows
│   ├── server/                API HTTP y WebSocket opcional
│   ├── persistence/           SQLx, repositorios y migraciones
│   ├── licensing/              Licencias, activación y revocación
│   ├── windows-platform/      Adaptadores para APIs nativas de Windows
│   ├── crypto/                Firmas, nonces y protección local
│   └── test-support/          Fixtures y servidor falso para pruebas
├── migrations/
├── installer/
│   ├── package.wxs             MSI o definición equivalente
│   └── assets/
├── docs/
└── .github/workflows/
    ├── test.yml
    └── release-sign.yml
```

El dashboard puede mantenerse temporalmente en PHP consumiendo la API Rust. Esto permite migrar el agente y el servidor sin cambiar todo en una sola entrega.

## 3. Componentes y responsabilidades

### `agent`

Servicio Windows que:

- genera una identidad de instalación en el primer arranque;
- crea y protege su clave privada;
- se enrola contra el servidor;
- verifica licencia local y estado de revocación;
- envía inventario mínimo con frecuencia configurable;
- recibe solo acciones tipadas;
- ejecuta cada acción con timeout, cancelación y límite de salida;
- registra eventos locales y los envía firmados;
- se detiene y desinstala de forma transparente.

### `server`

API que:

- autentica usuarios y agentes;
- administra tenants, planes y dispositivos;
- valida firmas, timestamps y nonces;
- gestiona la cola idempotente de acciones;
- aplica RBAC y aprobación de doble control;
- emite, renueva y revoca licencias;
- registra auditoría sin guardar secretos innecesarios.

### `licensing`

Módulo independiente del login administrativo. Verifica:

- producto y tenant;
- `license_id` y `key_id`;
- fecha de emisión y expiración;
- funcionalidades contratadas;
- número máximo de agentes;
- vínculo con la instalación;
- firma digital y estado de revocación.

### `windows-platform`

Única capa con llamadas Windows. El resto del sistema usa traits, de modo que el dominio pueda probarse en Linux sin simular toda la plataforma.

## 4. Flujo de funcionamiento

```text
Instalador firmado
       │
       ▼
Servicio Rust ── genera clave e identidad
       │
       ├── activa licencia
       │
       ├── enrola agente
       │
       └── check-in firmado ──► API Rust
                                  │
                                  ├── valida identidad/licencia
                                  ├── entrega acción tipada
                                  └── registra auditoría
       ◄──────── resultado firmado
```

Estados del agente:

```text
Installed → PendingActivation → Active → GracePeriod
                         │          │          │
                         └──────────┴──────► Expired

Active ──► Revoked
```

Estados de una acción:

```text
pending → approved → claimed → running → succeeded
                                      ├── failed
                                      ├── expired
                                      └── cancelled
```

El agente reclamará una acción con un `lease_id`. Si pierde conexión tras una
ejecución y antes de confirmar, el resultado puede ser incierto. No se debe
reenviar una acción con efectos indiscriminadamente: requiere reconciliación,
idempotencia o revisión manual. El lease limita reclamaciones concurrentes, pero
no demuestra ejecución exactamente una vez. La persistencia de nonce/command_id
y los leases aún no están implementados en las bibliotecas actuales.

## 5.1 Firma Ed25519 de comandos del servidor

La API no debe confiar únicamente en que una petición llegó por HTTPS. Cada
comando que pueda cambiar el estado de un equipo debe estar firmado por el
servidor con Ed25519. Esto permite verificar autenticidad e integridad en el
agente incluso después de atravesar proxies, colas o componentes intermedios.

La clave privada de firma debe vivir solo en un KMS/HSM o servicio de firma del
servidor. El agente contiene únicamente una o más claves públicas confiables.
La clave privada nunca se compila dentro del agente ni se entrega al cliente.

### Sobre de comando firmado

```json
{
  "protocol_version": 1,
  "key_id": "server-command-2026-01",
  "command_id": "cmd_01",
  "tenant_id": "tenant_01",
  "agent_id": "agent_01",
  "type": "lock_workstation",
  "parameters": {},
  "issued_at": "2026-10-07T15:00:00Z",
  "expires_at": "2026-10-07T15:05:00Z",
  "nonce": "random-unique-value",
  "signature": "base64url"
}
```

El JSON anterior ilustra los campos lógicos del diseño inicial, no el formato
de transporte implementado. La firma necesita un contrato de bytes estable:
o se preservan los bytes exactos transportados, o se define una representación
canónica. No se deben mezclar estas estrategias ni reconstruir el payload con
un serializador diferente antes de verificarlo.

**Contrato implementado el 11 de octubre:** el sobre real usa `key_id`,
`payload_b64` y `signature_b64`. Ed25519 firma el propósito, key_id y los bytes
JSON exactos transportados, con longitudes explícitas. El verificador no
reserializa el JSON. Es una alternativa de representación estable a JCS/CBOR,
no una implementación de estos formatos. Los detalles y las funciones reales
están en `punishell-rust/docs/EQUIVALENCIAS_FUNCIONES_RUST.md`.

Antes de ejecutar, el agente debe verificar, en este orden:

1. `key_id` pertenece al conjunto de claves públicas confiables.
2. La firma Ed25519 es válida sobre los bytes exactos del contrato versionado.
3. `tenant_id` y `agent_id` coinciden con la instalación.
4. `issued_at` y `expires_at` están dentro de la ventana permitida.
5. El `nonce` no se ha utilizado antes.
6. `command_id` no fue ejecutado previamente.
7. La licencia incluye la funcionalidad solicitada.
8. El rol y la política de aprobación permiten la acción.
9. El tipo y los parámetros pertenecen a una acción tipada permitida.

Para operaciones críticas se debe registrar una aprobación de otra persona con
MFA reciente. La implementación actual del contrato lleva `approval_id` firmado
por el servidor y una regla de doble control en `domain`. No implementa una
segunda firma humana. WebAuthn puede producir evidencia criptográfica vinculada
a la acción cuando se integre; un PIN TOTP no equivale a firma Ed25519 humana.

### Qué aporta cada capa

| Mecanismo | Protege | No sustituye |
|---|---|---|
| Authenticode | Identidad e integridad del ejecutable/instalador | Licencia ni autorización de comandos |
| TLS | Confidencialidad y transporte | Firma de aplicación y anti-replay |
| Ed25519 servidor | Autenticidad e integridad de cada comando | Cifrado del contenido |
| Ed25519 agente | Autenticidad de respuestas/check-ins | Autorización de usuario |
| TOTP/WebAuthn/RBAC | Identidad y permisos humanos | Identidad criptográfica del agente |

Ed25519 no cifra el comando; por eso se mantiene HTTPS. Tampoco evita por sí
solo el replay: para eso son obligatorios `nonce`, expiración, `command_id` y
estado idempotente en servidor y agente.

### Rotación y compromiso de claves

- Cada clave tiene un `key_id` y fecha de vigencia.
- El servidor publica un conjunto de claves públicas firmado por una clave raíz.
- El agente acepta temporalmente la clave anterior y la nueva durante la
  rotación.
- Una clave comprometida se revoca desde el servidor y se distribuye una nueva
  lista de confianza.
- Las acciones críticas pueden requerir dos claves distintas: servidor y
  aprobador.
- Cada verificación y rechazo se registra sin guardar material secreto.

## 5. APIs nativas de Windows

Se debe acceder a las APIs mediante el crate `windows` o una capa equivalente, manteniendo todos los `unsafe` aislados en `windows-platform` y cubiertos por pruebas.

| Necesidad | API Windows recomendada | Regla de diseño |
|---|---|---|
| Nombre del equipo | `GetComputerNameExW` | No usar comandos shell |
| IP y adaptadores | `GetAdaptersAddresses` | Normalizar IPv4/IPv6 y MAC |
| Espacio de disco | `GetDiskFreeSpaceExW` | Ruta configurable, no asumir siempre `C:` |
| RAM instalada | `GetPhysicallyInstalledSystemMemory` | Convertir a tipo numérico validado |
| Uptime | `GetTickCount64` | No depender de PowerShell |
| Usuario conectado | `GetUserNameW` o `WTSQuerySessionInformationW` | No enviar más información de la necesaria |
| Servicio Windows | Service Control Manager mediante `windows-service` | Servicio visible, con stop/restart correctos |
| Protección local | `CryptProtectData` / `CryptUnprotectData` | Proteger tokens y claves locales |
| Cámara | Windows Media Capture / Media Foundation | Solo con consentimiento y política explícita |
| Ubicación | Windows Location API | Solo con consentimiento; desactivada por defecto |
| Estado BitLocker | proveedor WMI/Windows autorizado | No extraer recovery keys por defecto |
| HTTPS | `WinHTTP` o cliente Rust TLS | Validación de certificados obligatoria |

La captura de cámara, ubicación y recuperación de BitLocker deben ser módulos opcionales con permisos, motivo de uso, retención y auditoría. No deben formar parte del inventario silencioso estándar.

### Servicio Windows

El binario debe registrarse como un servicio normal, con:

- nombre visible y descripción clara;
- inicio automático configurable;
- eventos de inicio, parada y error;
- recuperación limitada ante fallos;
- permisos mínimos;
- instalador y desinstalador verificables;
- ningún WMI watchdog, `Run`, `SetupComplete`, carpeta oculta o exclusión de Defender.

## 6. Protocolo de API

Todas las llamadas deben usar HTTPS y JSON versionado.

### Enrolamiento

```http
POST /v1/agents/enroll
```

```json
{
  "activation_code": "PSH-6M-XXXX-XXXX",
  "public_key": "base64url",
  "device_info": {
    "hostname": "equipo-01",
    "os": "Windows"
  }
}
```

Respuesta:

```json
{
  "agent_id": "uuid",
  "tenant_id": "uuid",
  "license_id": "uuid",
  "access_token": "short-lived-token",
  "expires_at": "2030-04-07T12:00:00Z"
}
```

El código de activación es de un solo uso y se almacena hasheado en el servidor. No contiene la clave privada ni la licencia completa.

### Check-in

```http
POST /v1/agents/{agent_id}/heartbeat
Authorization: Bearer <token>
X-Request-Id: <uuid>
X-Signature: <signature>
```

El contenido firmado incluye método, ruta, hash del cuerpo, timestamp y nonce. El servidor rechaza timestamps fuera de ventana, nonces repetidos y tokens revocados.

### Acciones

```http
POST /v1/endpoints/{endpoint_id}/actions
GET  /v1/actions/{action_id}
POST /v1/actions/{action_id}/approve
POST /v1/actions/{action_id}/cancel
```

Ejemplo seguro:

```json
{
  "type": "lock_workstation",
  "parameters": {},
  "reason": "Equipo reportado como perdido",
  "expires_at": "2026-10-08T02:00:00Z"
}
```

No se debe aceptar algo equivalente a `command_string: "powershell ..."` como interfaz principal.

## 7. Modelo de activación por 6 meses o más

### Planes sugeridos

Los nombres son comerciales y pueden cambiar sin afectar el protocolo:

| Plan | Vigencia | Uso |
|---|---:|---|
| `starter_6m` | 6 meses | Piloto o instalación inicial |
| `business_12m` | 12 meses | Operación anual |
| `enterprise_24m` | 24 meses | Contrato de largo plazo |
| `custom` | Definida por contrato | Features y cupos personalizados |

La duración se calcula en el servidor al emitir la licencia. El cliente nunca debe poder ampliar `expires_at` modificando un archivo local.

### Token firmado

```json
{
  "license_id": "lic_01",
  "tenant_id": "tenant_01",
  "product": "punishell-mdm",
  "plan": "starter_6m",
  "features": ["inventory", "lock_workstation"],
  "max_agents": 25,
  "issued_at": "2026-10-07T15:00:00Z",
  "expires_at": "2027-04-07T15:00:00Z",
  "offline_grace_hours": 72,
  "key_id": "license-key-2026-01",
  "signature": "base64url"
}
```

La firma se genera en el servidor con una clave privada Ed25519. El agente contiene únicamente la clave pública y verifica el token antes de habilitar funcionalidades.

### Activación de una cuenta

1. El administrador crea una cuenta/tenant en el portal.
2. Selecciona el plan de 6, 12, 24 meses o personalizado.
3. El servidor crea la licencia y un código de activación de un solo uso.
4. El código se entrega al cliente por el portal o correo administrativo seguro.
5. Durante la instalación, el operador introduce el código.
6. El agente genera una clave de dispositivo local.
7. `POST /v1/agents/enroll` intercambia el código por `agent_id`, token corto y licencia firmada.
8. El servidor consume el código y vincula la licencia al `agent_id`.
9. El agente protege el token localmente y comienza el check-in.

El código debe tener expiración corta, por ejemplo 15 minutos, máximo de intentos y revocación manual. Para instalaciones masivas se puede usar un código de enrolamiento limitado por tenant y número de dispositivos, nunca una clave maestra compartida.

### Renovación y expiración

- Renovación online antes de `expires_at`.
- Gracia offline limitada, por ejemplo 72 horas.
- En expiración, el agente conserva solo funciones locales de diagnóstico y deja de ejecutar acciones administrativas.
- Revocación inmediata desde el servidor.
- Reemplazo de claves de firma mediante `key_id` y un conjunto de claves públicas confiables.
- Verificación de hora del servidor para reducir manipulación del reloj local.

La activación no reemplaza el login de usuarios. El portal seguirá usando usuarios, roles, MFA y autorización de acciones separadamente.

## 8. Protección local de la activación

El token y la clave privada del agente no deben guardarse en texto plano.

- Usar `CryptProtectData`/`CryptUnprotectData` para proteger el material local.
- Si el servicio corre como `LocalSystem`, aplicar ACL estrictas al archivo de configuración.
- Para secretos ligados a una máquina se puede usar `CRYPTPROTECT_LOCAL_MACHINE`, considerando que su alcance permite descifrado por usuarios de esa máquina; no debe tratarse como una frontera absoluta.
- Para una protección más fuerte, evaluar DPAPI-NG, CNG/TPM o Credential Manager.
- Nunca incrustar una clave privada de licenciamiento en el ejecutable.

Microsoft documenta que DPAPI incluye integridad del dato y que el alcance por defecto suele vincularse al mismo usuario y equipo; también documenta las limitaciones de protección entre equipos.

## 9. Firma del ejecutable para Windows

### Qué se firma

Debe firmarse cada artefacto distribuido:

- servicio `.exe`;
- instalador `.msi` o paquete `.msix`;
- DLLs auxiliares;
- scripts PowerShell distribuidos, si los hubiera;
- manifiestos y catálogo cuando aplique.

### Opción recomendada

Para distribución fuera de Microsoft Store, Microsoft recomienda Azure Artifact Signing, antes llamado Trusted Signing. Usa un modelo de confianza pública o privada y mantiene el certificado de firma en el servicio; el certificado privado no se descarga al equipo de desarrollo.

Proceso general:

1. Crear suscripción Azure y tenant Microsoft Entra.
2. Crear recurso Artifact Signing.
3. Completar validación de identidad de persona u organización.
4. Crear un certificado profile de confianza pública.
5. Asignar el rol de firmante solo a la identidad de CI/CD.
6. Instalar SignTool y las herramientas de integración.
7. Firmar en CI, no desde un portátil personal.
8. Aplicar timestamp RFC 3161.
9. Verificar la firma antes de publicar.

La disponibilidad de confianza pública depende de la región y del tipo de identidad. Si el país o perfil no es elegible, se debe usar un certificado tradicional OV de una CA reconocida. Los certificados autofirmados son solo para desarrollo/laboratorio.

### Firma con SignTool

SignTool forma parte del Windows SDK. El comando exacto depende de si se usa un certificado OV local o Artifact Signing, pero la política debe ser equivalente:

```powershell
signtool sign /fd SHA256 /tr <timestamp-url> /td SHA256 <archivo.exe>
signtool verify /pa /v <archivo.exe>
```

Para Artifact Signing se utiliza la integración oficial con `dlib` y un archivo de metadatos del perfil. El certificado de Artifact Signing tiene una vigencia operativa corta, por lo que el timestamp es obligatorio para que las firmas continúen validando después.

### Pipeline de publicación

```text
commit firmado/verificado
        │
        ├── cargo fmt --check
        ├── cargo clippy -- -D warnings
        ├── cargo test
        ├── cargo build --release --target x86_64-pc-windows-msvc
        ├── generar MSI/MSIX
        ├── firmar EXE + instalador
        ├── verificar Authenticode
        ├── publicar checksum/SBOM
        └── crear release
```

La cuenta que firma no debe tener permisos de despliegue innecesarios. El pipeline debe registrar quién firmó, qué commit se compiló y qué hashes fueron publicados.

## 10. Rendimiento esperado y medición

Rust puede reducir consumo y tiempo de arranque del agente, y Tokio permite manejar I/O concurrente sin crear un proceso o hilo por operación. Pero el cuello de botella actual está también en polling, red, consultas SQL y almacenamiento de resultados.

Métricas antes y después:

- memoria residente en reposo;
- tiempo de arranque del servicio;
- CPU durante 24 horas;
- duración p50/p95 de check-in;
- consumo de red por agente;
- tiempo de reclamación y confirmación de una acción;
- duplicaciones de acciones;
- tamaño firmado del instalador;
- tiempo de recuperación después de perder red.

El agente debe usar backoff adaptativo: intervalo normal, intervalo corto solo durante una sesión aprobada y pausa progresiva ante errores. Para muchos agentes se puede evaluar conexión persistente, pero el polling HTTPS simple suele ser más fácil de operar detrás de firewalls.

## 11. Entrega por fases

1. **Fundación:** workspace, protocolo, configuración, logging y migraciones.
2. **Agente mínimo:** enrolamiento, licencia, heartbeat e inventario no sensible.
3. **API Rust:** autenticación de agentes, cola idempotente y auditoría.
4. **Acciones seguras:** bloqueo, diagnóstico y operaciones tipadas.
5. **Portal:** migrar dashboard y RBAC.
6. **Firma:** CI/CD, Artifact Signing u OV, instalador firmado.
7. **Escala:** pruebas con muchos agentes, renovación y revocación.
8. **Retirada:** apagar endpoints PHP, Python y scripts de persistencia anterior.

## 12. Criterios de aceptación

- Un ejecutable no firmado no se distribuye.
- Un agente no enrolado no recibe acciones.
- Un código de activación solo se usa una vez.
- Una licencia de 6 meses vence en servidor y agente sin depender únicamente del reloj local.
- Una licencia revocada deja de habilitar acciones administrativas.
- La clave privada de firma nunca sale del servicio de firma o del almacén seguro.
- No existen bypasses de desarrollo en producción.
- No se ejecuta shell arbitrario como contrato de API.
- El servicio es visible, desinstalable y compatible con Defender.
- Las funciones de cámara, ubicación y BitLocker requieren política, consentimiento y auditoría.

## Referencias oficiales

- [SignTool de Windows](https://learn.microsoft.com/en-us/windows/desktop/seccrypto/signtool)
- [Opciones de firma de código para Windows](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [Azure Artifact Signing](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)
- [Integración de Artifact Signing con SignTool](https://learn.microsoft.com/en-us/azure/trusted-signing/how-to-signing-integrations)
- [CryptProtectData / DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
