# Versiones, paquetes e instalación

La distribución actual tiene dos componentes: servidor Linux x86_64 y agente
Windows x86_64. El ZIP de Windows incluye los scripts de instalación y retirada;
el TAR de Linux incluye instalador y unidad systemd. No son paquetes MSI, DEB ni
RPM. El agente Linux sólo tiene soporte parcial de consola y no se distribuye
como equivalente del agente Windows. El servidor Windows tampoco forma parte
de estos paquetes.

## 1. Preparar una versión

La versión vigente se define en `[workspace.package]` de
`punishell-rust/Cargo.toml`. Para una nueva entrega, cambiarla, por ejemplo de
`0.1.0` a `0.1.1`, actualizar `Cargo.lock` mediante `cargo check --workspace` y
registrar ambos archivos. No volver a publicar otro binario bajo el mismo tag.

Antes de distribuir:

```bash
cd punishell-rust
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Los instaladores no contienen claves, CA, dirección IP, licencias ni activación.
Esos datos se provisionan por separado para cada laboratorio. Ver la sección
de IP manual del README técnico del repositorio.

## 2. Generar binarios con GitHub Actions

Primero activar el workflow preparado en
`punishell-rust/tools/github-packages.yml`. La credencial utilizada para subir
este repositorio actualmente no tiene alcance OAuth `workflow`; por eso se
conserva como archivo de preparación fuera de `.github/workflows/` y Actions
todavía no aparece disponible. Con una credencial autorizada para modificar
workflows, copiarlo a su ubicación activa y subirlo:

```bash
mkdir -p .github/workflows
cp punishell-rust/tools/github-packages.yml .github/workflows/packages.yml
git add .github/workflows/packages.yml
git commit -m "Enable Linux and Windows package builds"
git push origin main
```

Alternativamente, el propietario puede crear ese archivo desde GitHub web
usando el contenido preparado. No pegar credenciales en archivos ni en el chat.
Los pasos siguientes aplican una vez activado.

En el repositorio, abrir **Actions → Build Linux and Windows packages → Run
workflow**, seleccionar `main` y ejecutar. Esto compila y prueba en runners Linux
y Windows reales. Al finalizar correctamente, descargar los artefactos
`linux-server` y `windows-agent-unsigned` desde la ejecución. Se conservan 14 días;
para distribución duradera, subir los paquetes a Releases.

También se puede usar GitHub CLI desde la raíz del repositorio:

```bash
gh workflow run packages.yml --ref main
gh run list --workflow packages.yml
gh run view NUMERO_DE_EJECUCION
gh run download NUMERO_DE_EJECUCION --dir dist/downloaded
```

El runner Linux usa Ubuntu 24.04 y genera binarios GNU/glibc x64; verificar la
compatibilidad en otras distribuciones. El runner Windows usa MSVC y Windows SDK.
La compilación Windows no sustituye pruebas de servicio, TPM, BitLocker ni
actualización sobre una VM descartable.

Los archivos generados incluyen:

- `punishell-server-VERSION-linux-x86_64.tar.gz` y su `.sha256`.
- `punishell-agent-VERSION-windows-x86_64-unsigned.zip` y su `.sha256`.
- `punishell-agent-VERSION-windows-x86_64-unsigned.exe` y su `.sha256`.

**El agente unsigned es un resultado de compilación, no un instalador listo para
producción.** El instalador lo rechazará hasta que esté firmado con Authenticode
válido. No deshabilitar esa comprobación. El workflow no tiene certificado privado
de firma ni intenta obtenerlo del código.

## 3. Compilar y empaquetar localmente

En Linux x64, desde la raíz:

```bash
bash punishell-rust/tools/package_linux.sh
```

El script compila en release, copia únicamente binario, scripts y manuales a un
TAR, y genera SHA-256 en `dist/`. Usa las bibliotecas del host de compilación;
para reproducir la plataforma oficial, usar Ubuntu 24.04. Rechaza sobrescribir
un artefacto existente: conservarlo o moverlo antes de generar otro.

En Windows con Rust 1.97.1, MSVC y Windows SDK:

```powershell
cd punishell-rust
cargo build --release -p punishell-agent --target x86_64-pc-windows-msvc --locked
# Volver a la raíz del repositorio.
cd ..
```

Firmar el EXE generado, con el certificado de editor ya provisionado en esa
máquina. Con SignTool disponible en PATH:

```powershell
signtool sign /fd SHA256 /tr https://timestamp.digicert.com /td SHA256 /a `
  .\punishell-rust\target\x86_64-pc-windows-msvc\release\punishell-agent.exe
signtool verify /pa /v `
  .\punishell-rust\target\x86_64-pc-windows-msvc\release\punishell-agent.exe

.\punishell-rust\tools\package_windows.ps1 `
  -Executable .\punishell-rust\target\x86_64-pc-windows-msvc\release\punishell-agent.exe
```

También se puede firmar el EXE unsigned descargado de Actions y pasarlo al mismo
script. El paquete firmado pierde el sufijo `-unsigned` e incluye el pin público
`signer-certificate-sha256.txt`. Para generar sólo un paquete de compilación sin
firma, pasar `-AllowUnsigned` explícitamente. Siempre firmar **antes** de calcular
hashes y crear los ZIP: la firma cambia el contenido del EXE.

## 4. Instalar el servidor Linux

Verificar y extraer el paquete en una máquina con systemd:

```bash
sha256sum -c punishell-server-0.1.0-linux-x86_64.tar.gz.sha256
tar -xzf punishell-server-0.1.0-linux-x86_64.tar.gz
cd punishell-server-0.1.0-linux-x86_64
sudo bash install_server_linux.sh
```

El instalador crea la cuenta de sistema `punishell`, instala el binario en
`/usr/local/bin`, prepara `/var/lib/punishell` y registra el servicio. No inicia
ni habilita el servicio hasta que exista una configuración válida. Una instalación
posterior conserva estado y claves y exige detener primero el servicio.

Preparar certificados TLS con la IP real en SAN, siguiendo el README técnico.
Copiar el certificado y la clave TLS del servidor, junto a la clave pública
del proveedor, con estos permisos:

```bash
sudo install -o root -g punishell -m 0640 /ruta/server.pem /etc/punishell/server.pem
sudo install -o root -g punishell -m 0640 /ruta/server.key /etc/punishell/server.key
sudo install -o root -g punishell -m 0640 /ruta/license-public.json /etc/punishell/license-public.json
sudo -u punishell /usr/local/bin/punishell-server init \
  --config /var/lib/punishell/server.json \
  --state-dir /var/lib/punishell/state \
  --public-url https://192.168.1.50:8443 \
  --certificate /etc/punishell/server.pem \
  --private-key /etc/punishell/server.key \
  --license-public-key /etc/punishell/license-public.json
```

Guardar la contraseña y el secreto TOTP inicial. Sustituir la IP del ejemplo por
la real y editar `bind` en `/var/lib/punishell/server.json` a esa misma
`IP:8443`; conservar el resto de campos. Permitir TCP 8443 en la red de pruebas.

```bash
sudo systemctl enable --now punishell-server
sudo systemctl status punishell-server
sudo journalctl -u punishell-server -n 100 --no-pager
curl --fail --cacert /ruta/lab-ca.pem https://192.168.1.50:8443/health/ready
```

El servicio tiene `ProtectHome=true`: certificados y estado deben estar en las
rutas anteriores, no en `/home`. Para actualizar el servidor: respaldar base y
claves con el servicio detenido, instalar el nuevo paquete y volver a iniciarlo.
Las migraciones son automáticas; no se garantiza que un binario antiguo pueda
abrir un esquema nuevo. Un rollback requiere restaurar conjuntamente la copia
anterior compatible, sus claves y el binario.

## 5. Instalar el cliente Windows con IP manual

Extraer el ZIP **firmado**, añadir `trust.json` público y `lab-ca.pem`, y ejecutar
en PowerShell elevado, desde la carpeta extraída:

```powershell
Test-NetConnection -ComputerName 192.168.1.50 -Port 8443
$pin = (Get-Content .\signer-certificate-sha256.txt -Raw).Trim()
.\install_agent_rust.ps1 -AgentExe .\punishell-agent.exe `
  -TrustPath .\trust.json -ServerUrl https://192.168.1.50:8443 `
  -Tenant main -SignerCertificateSha256 $pin -CaCertificate .\lab-ca.pem
Get-Service PuniShellAgent
```

Antes, importar en el panel la licencia firmada del proveedor; el operador
técnico crea el código de activación. Copiar previamente `license-public.json`
a `/etc/punishell/` con lectura para el usuario `punishell`. La herramienta
`punishell-license` y su clave privada permanecen exclusivamente en el proveedor. La CA HTTPS y la
confianza del certificado de firma del EXE son independientes. No incluir claves
privadas del servidor ni del editor dentro de un ZIP o de GitHub Releases.

## 6. Subir una versión a GitHub Releases

Una vez que los commits estén en `main`, crear el tag que coincide exactamente
con la versión del workspace:

```bash
git tag -a v0.1.0 -m "PuniShell 0.1.0"
git push origin v0.1.0
```

Con el workflow activado, compila las dos plataformas y, si ambas pasan, crea una **prerelease
en borrador** con los archivos. Revisarla en **Releases**, añadir notas y los
paquetes Windows firmados antes de publicarla. El borrador no constituye una
entrega de producción y sus paquetes unsigned siguen claramente identificados.
Si una compilación falla, no se crea el borrador: consultar los logs de Actions.

Para cargar manualmente archivos ya comprobados:

```bash
gh release create v0.1.0 --verify-tag --draft --prerelease \
  --title "PuniShell 0.1.0" --notes "Prueba de concepto; consultar limitaciones y requisitos de firma."
gh release upload v0.1.0 dist/ARCHIVO.tar.gz dist/ARCHIVO.tar.gz.sha256
```

Si ya existe el borrador, omitir `release create`. Repetir `release upload` con
ZIP, EXE y sus hashes firmados. Evitar sobrescribir archivos de una versión ya
publicada: corregir la versión y generar otra entrega. La carpeta `dist/` se
excluye de Git; los binarios se comparten mediante artefactos o Releases.

## 7. Cargar una actualización de agente en PuniShell

GitHub Releases distribuye paquetes; el agente no instala directamente desde
GitHub. En el servidor, copiar el **EXE firmado**, verificar su SHA-256 y publicar
el manifiesto con una versión SemVer mayor que la instalada:

```bash
sudo -u punishell /usr/local/bin/punishell-server publish-update \
  --config /var/lib/punishell/server.json \
  --file /ruta/accesible/punishell-agent-0.1.1-windows-x86_64.exe \
  --channel stable --version 0.1.1 \
  --signer-certificate-sha256 SHA256_DEL_CERTIFICADO_EDITOR
```

La cuenta `punishell` debe poder leer ese archivo. El pin debe estar permitido en
los agentes y debe coincidir con el certificado que firmó el EXE. Solicitar la
acción de actualización desde el panel como operador y aprobarla desde otra
cuenta con TOTP. Comprobar versión, heartbeat y auditoría después del cambio.
Si cambia el certificado editor, preparar primero su confianza en los clientes;
publicar el EXE no actualiza automáticamente los pins.
