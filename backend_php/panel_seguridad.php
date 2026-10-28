<?php
// backend_php/panel_seguridad.php
$conn = new mysqli("localhost", "root", "", "punishell_db");

// Obtener solicitudes pendientes para la bandeja de Don Claudio
$pendientes = $conn->query("SELECT id, endpoint_id, command_type, created_at FROM endpoint_commands WHERE status = 'pending' ORDER BY created_at DESC");
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Easton Design | PuniShell MDM</title>
    <style>
        :root { --bg: #1e1e2e; --panel: #282a36; --text: #f8f8f2; --accent: #ff79c6; --green: #50fa7b; --red: #ff5555; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; display: flex; gap: 20px; }
        .col { flex: 1; background: var(--panel); padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h2 { border-bottom: 2px solid var(--accent); padding-bottom: 10px; margin-top: 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #444; }
        th { color: var(--accent); }
        button { background: var(--accent); color: #fff; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; font-weight: bold; transition: 0.3s; }
        button:hover { opacity: 0.8; }
        .btn-danger { background: var(--red); }
        .btn-success { background: var(--green); color: #000; }
        
        /* Modal Styles */
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); justify-content: center; align-items: center; }
        .modal { background: var(--panel); padding: 30px; border-radius: 8px; width: 350px; text-align: center; border: 1px solid var(--accent); }
        .modal input { width: 80%; padding: 10px; font-size: 24px; text-align: center; letter-spacing: 5px; margin: 15px 0; background: #111; color: var(--green); border: 1px solid #555; }
    </style>
</head>
<body>

    <div class="col">
        <h2>🛡️ Operador Táctico (Nivel 2)</h2>
        <p>Inventario de Equipos Activos:</p>
        <table>
            <tr><th>ID Equipo</th><th>Hostname</th><th>Acción Crítica</th></tr>
            <tr>
                <td>1</td>
                <td>DESKTOP-EASTON-01</td>
                <td>
                    <button onclick="solicitarComando(1, 'Calculadora', 'calc.exe')">Solicitar Calc</button>
                    <button class="btn-danger" onclick="solicitarComando(1, 'KillBill', 'shutdown /s /t 10')">KillBill</button>
                </td>
            </tr>
        </table>
    </div>

    <div class="col">
        <h2>👑 Bandeja Jefatura (Nivel 3)</h2>
        <p>Pendientes de Autorización TOTP:</p>
        <table>
            <tr><th>ID Solicitud</th><th>Protocolo</th><th>Equipo ID</th><th>Acción</th></tr>
            <?php while($row = $pendientes->fetch_assoc()): ?>
            <tr>
                <td>#<?= $row['id'] ?></td>
                <td><strong style="color:var(--red)"><?= $row['command_type'] ?></strong></td>
                <td><?= $row['endpoint_id'] ?></td>
                <td>
                    <button class="btn-success" onclick="abrirModal(<?= $row['id'] ?>)">🔑 Autorizar</button>
                </td>
            </tr>
            <?php endwhile; ?>
            <?php if($pendientes->num_rows == 0) echo "<tr><td colspan='4'>No hay solicitudes pendientes.</td></tr>"; ?>
        </table>
    </div>

    <div class="modal-overlay" id="authModal">
        <div class="modal">
            <h3 style="color:var(--accent)">Validación Requerida</h3>
            <p>Ingrese el código de 6 dígitos de su Microsoft Authenticator para liberar la acción.</p>
            <input type="text" id="totpInput" maxlength="6" placeholder="000000" autocomplete="off">
            <input type="hidden" id="currentCommandId">
            <br>
            <button class="btn-success" onclick="enviarAutorizacion()">Validar y Liberar</button>
            <button style="background:#555; margin-left:10px;" onclick="cerrarModal()">Cancelar</button>
        </div>
    </div>

    <script>
        // 1. Enviar solicitud al servidor sin recargar
        function solicitarComando(endpointId, type, cmdString) {
            if(!confirm(`¿Seguro que deseas solicitar la ejecución de ${type}?`)) return;

            let data = new FormData();
            data.append('endpoint_id', endpointId);
            data.append('command_type', type);
            data.append('command_string', cmdString);

            fetch('solicitar_accion.php', { method: 'POST', body: data })
            .then(res => res.json())
            .then(data => {
                alert(data.message);
                location.reload(); // Recargamos para que aparezca en la bandeja de Jefatura
            });
        }

        // 2. Control del Modal
        function abrirModal(commandId) {
            document.getElementById('currentCommandId').value = commandId;
            document.getElementById('totpInput').value = '';
            document.getElementById('authModal').style.display = 'flex';
            document.getElementById('totpInput').focus();
        }

        function cerrarModal() {
            document.getElementById('authModal').style.display = 'none';
        }

        // 3. Enviar el PIN al servidor
        function enviarAutorizacion() {
            let cmdId = document.getElementById('currentCommandId').value;
            let pin = document.getElementById('totpInput').value;

            if(pin.length !== 6) {
                alert("El código debe tener 6 dígitos."); return;
            }

            let data = new FormData();
            data.append('command_id', cmdId);
            data.append('totp_pin', pin);

            fetch('autorizar_accion.php', { method: 'POST', body: data })
            .then(res => res.json())
            .then(data => {
                if(data.status === 'success') {
                    alert("✅ " + data.message);
                    location.reload(); // Recargamos para limpiar la bandeja
                } else {
                    alert("❌ Error: " + data.message);
                }
            });
        }
    </script>
</body>
</html>