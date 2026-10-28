<?php
// backend_php/autorizar_accion.php
session_start();

// 1. CARGA DE LIBRERÍA (Basado en tu árbol de archivos: totp.php está en la raíz)
if (file_exists('totp.php')) {
    require_once 'totp.php';
} else {
    header('Content-Type: application/json');
    die(json_encode(["status" => "error", "message" => "Error crítico: No se encuentra el archivo totp.php en el servidor."]));
}

header('Content-Type: application/json; charset=utf-8');

// 2. CONEXIÓN A LA BD
$conn = new mysqli("localhost", "root", "", "punishell_db");

if ($conn->connect_error) {
    die(json_encode(["status" => "error", "message" => "Falla de conexión BD"]));
}

// 3. SEGURIDAD: Solo Nivel 3 (Jefatura)
if (!isset($_SESSION['user_id']) || $_SESSION['nivel'] != 3) {
    http_response_code(403);
    echo json_encode(["status" => "error", "message" => "Acceso denegado: Se requiere firma de Jefatura."]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $command_id = intval($_POST['command_id'] ?? 0);
    $user_id_actual = $_SESSION['user_id'];
    $accion = $_POST['status'] ?? ''; // 'approved' o 'rejected'

    if ($command_id === 0) {
        echo json_encode(["status" => "error", "message" => "ID de comando no válido."]);
        exit;
    }

    // --- ESCENARIO A: RECHAZAR ---
    if ($accion === 'rejected') {
        $update = $conn->prepare("UPDATE endpoint_commands SET status = 'rejected', id_autorizador = ?, fecha_aprobacion = NOW() WHERE id = ?");
        $update->bind_param("ii", $user_id_actual, $command_id);
        
        if ($update->execute()) {
            echo json_encode(["status" => "success", "message" => "Protocolo rechazado y eliminado."]);
        } else {
            echo json_encode(["status" => "error", "message" => "Error al procesar el rechazo en la BD."]);
        }
        exit;
    }

    // --- ESCENARIO B: APROBAR (Con TOTP) ---
    if ($accion === 'approved') {
        $pin_ingresado = $_POST['totp_pin'] ?? '';

        if (empty($pin_ingresado)) {
            echo json_encode(["status" => "error", "message" => "Debe ingresar el PIN de Authenticator."]);
            exit;
        }

        // Obtener secreto del Jefe actual
        $stmt = $conn->prepare("SELECT totp_secret FROM usuarios WHERE id = ?");
        $stmt->bind_param("i", $user_id_actual);
        $stmt->execute();
        $user_data = $stmt->get_result()->fetch_assoc();

        if (!$user_data || empty($user_data['totp_secret'])) {
            echo json_encode(["status" => "error", "message" => "Su usuario no tiene semilla TOTP configurada."]);
            exit;
        }

        // VALIDACIÓN TOTP (Microsoft Authenticator o Modo Dev 000000)
        // Nota: Asegúrate que la clase en totp.php se llame SimpleTOTP
        if ($pin_ingresado === '000000' || SimpleTOTP::verifyCode($user_data['totp_secret'], $pin_ingresado)) {
            
            // 4. IDENTIFICAR QUÉ ESTAMOS AUTORIZANDO
            $cmd_query = $conn->prepare("SELECT endpoint_id, command_type FROM endpoint_commands WHERE id = ?");
            $cmd_query->bind_param("i", $command_id);
            $cmd_query->execute();
            $cmd_info = $cmd_query->get_result()->fetch_assoc();

            if (!$cmd_info) {
                echo json_encode(["status" => "error", "message" => "Comando no encontrado en la base de datos."]);
                exit;
            }

            $endpoint_id = $cmd_info['endpoint_id'];

            if ($cmd_info['command_type'] === 'open_tunnel') {
                // --- LÓGICA ESPECIAL: ABRIR TÚNEL POR 30 MINUTOS ---
                // Seteamos la sesión activa y la expiración 30 min adelante
                $sql_tunnel = "UPDATE easton_endpoints 
                               SET terminal_session_active = 1, 
                                   terminal_expires_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE) 
                               WHERE id = ?";
                $stmt_tunnel = $conn->prepare($sql_tunnel);
                $stmt_tunnel->bind_param("i", $endpoint_id);
                $stmt_tunnel->execute();

                $nuevo_estado = 'executed'; // Se marca ejecutado porque el túnel ya se abrió
                $mensaje_final = "¡Túnel abierto! Acceso concedido por 30 minutos.";
            } else {
                // --- LÓGICA NORMAL: COMANDOS (calc, lock, etc.) ---
                $nuevo_estado = 'approved';
                $mensaje_final = "¡Protocolo autorizado exitosamente!";
            }

            // 5. ACTUALIZAR ESTADO DEL COMANDO
            $update = $conn->prepare("UPDATE endpoint_commands SET status = ?, id_autorizador = ?, fecha_aprobacion = NOW() WHERE id = ?");
            $update->bind_param("sii", $nuevo_estado, $user_id_actual, $command_id);
            $update->execute();

            echo json_encode(["status" => "success", "message" => $mensaje_final]);
        } else {
            echo json_encode(["status" => "error", "message" => "Código de seguridad incorrecto."]);
        }
        exit;
    }
}

echo json_encode(["status" => "error", "message" => "Método no permitido."]);
?>