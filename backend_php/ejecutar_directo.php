<?php
// backend_php/ejecutar_directo.php
session_start();
header('Content-Type: application/json; charset=utf-8');

$conn = new mysqli("127.0.0.1", "root", "", "punishell_db");

if ($conn->connect_error) {
    echo json_encode(["status" => "error", "message" => "Error de conexión BD: " . $conn->connect_error]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    $endpoint_id = isset($_POST['endpoint_id']) ? intval($_POST['endpoint_id']) : 0;
    $command_text = isset($_POST['command']) ? trim($_POST['command']) : '';

    if ($endpoint_id === 0 || empty($command_text)) {
        echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
        exit;
    }

    // 1. Verificamos que el túnel realmente esté activo en la DB (Modo Turbo)
    $res = $conn->query("SELECT terminal_session_active FROM easton_endpoints WHERE id = $endpoint_id");
    $row = $res->fetch_assoc();

    if ($row && $row['terminal_session_active'] == 1) {
        
        // 2. Insertamos el comando en la fila de espera.
        // OJO AQUÍ: Forzamos la columna 'output' a estar vacía ('') para que el CONCAT del streaming no falle.
        $sql = "INSERT INTO endpoint_commands (endpoint_id, command_type, command_string, status, is_interactive, output) 
                VALUES (?, 'custom', ?, 'approved', 1, '')";
        
        $stmt = $conn->prepare($sql);
        
        // Si la tabla no tiene las columnas is_interactive u output, esto nos dirá exactamente por qué falló
        if (!$stmt) {
            echo json_encode(["status" => "error", "message" => "Error SQL crítico: " . $conn->error]);
            exit;
        }

        $stmt->bind_param("is", $endpoint_id, $command_text);
        
        if ($stmt->execute()) {
            // ¡ÉXITO! Devolvemos el ID para que el JavaScript empiece a escuchar
            echo json_encode(["status" => "success", "command_id" => $conn->insert_id]);
        } else {
            echo json_encode(["status" => "error", "message" => "Fallo al insertar comando: " . $stmt->error]);
        }
        
        $stmt->close();
    } else {
        echo json_encode(["status" => "error", "message" => "Túnel cerrado. Refresca e ingresa el PIN."]);
    }
} else {
    echo json_encode(["status" => "error", "message" => "Método no autorizado."]);
}

$conn->close();
?>