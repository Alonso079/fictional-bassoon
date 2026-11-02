#!/usr/bin/env bash
# Run from an extracted Linux server package. Initialization is explicit.
set -euo pipefail
package_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $(id -u) != 0 ]]; then
    echo 'Ejecutar con sudo bash install_server_linux.sh.' >&2
    exit 1
fi
for program in systemctl install getent useradd; do
    command -v "$program" >/dev/null || { echo "Falta $program" >&2; exit 1; }
done
[[ -f "$package_dir/punishell-server" && -f "$package_dir/punishell-server.service" ]] || {
    echo 'Ejecutar el instalador desde el paquete Linux completo.' >&2; exit 1;
}
if systemctl is-active --quiet punishell-server; then
    echo 'Detener primero: sudo systemctl stop punishell-server' >&2
    exit 1
fi
if ! getent passwd punishell >/dev/null; then
    useradd --system --user-group --home-dir /var/lib/punishell --shell /usr/sbin/nologin punishell
fi
install -d -o punishell -g punishell -m 0700 /var/lib/punishell
install -d -o root -g punishell -m 0750 /etc/punishell
install -o root -g root -m 0755 "$package_dir/punishell-server" /usr/local/bin/punishell-server
install -o root -g root -m 0644 "$package_dir/punishell-server.service" /etc/systemd/system/punishell-server.service
systemctl daemon-reload
echo 'Binario y servicio instalados; no se modificaron claves ni bases de datos.'
echo 'Configurar TLS e inicializar como usuario punishell según RELEASES.md.'
echo 'Después: sudo systemctl enable --now punishell-server'
