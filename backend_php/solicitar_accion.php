<?php
// backend_php/solicitar_accion.php
session_start();
header('Content-Type: application/json');

// 1. Conexión a la Base de Datos
$conn = new mysqli("localhost", "root", "", "punishell_db");

if ($conn->connect_error) {
    echo json_encode(["status" => "error", "message" => "Fallo de conexión a la BD"]);
    exit;
}

// 2. EL GUARDIÁN DE SEGREGACIÓN (Maker-Checker)
// Solo el Nivel 2 (Operador) puede SOLICITAR. 
if (!isset($_SESSION['user_id']) || $_SESSION['nivel'] != 2) {
    http_response_code(403);
    echo json_encode([
        "status" => "error", 
        "message" => "VIOLACIÓN DE SEGREGACIÓN DE FUNCIONES: La Jefatura no puede iniciar solicitudes tácticas. Solo un Operador (Maker) puede realizar esta acción."
    ]);
    exit;
}

// 3. Procesar la Solicitud
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $endpoint_id = intval($_POST['endpoint_id']);
    $command_type = $_POST['command_type'];
    $command_string = $_POST['command_string'];
    $id_solicitante = $_SESSION['user_id']; // Tomamos el ID real de la sesión

    // Insertar comando en estado 'pending'
    $stmt = $conn->prepare("INSERT INTO endpoint_commands (endpoint_id, command_type, command_string, status, id_solicitante) VALUES (?, ?, ?, 'pending', ?)");
    $stmt->bind_param("issi", $endpoint_id, $command_type, $command_string, $id_solicitante);
    
    if ($stmt->execute()) {
        $solicitud_id = $conn->insert_id;
        
        // Opcional: Notificación por correo a Nivel 3 aquí
        
        echo json_encode([
            "status" => "success", 
            "message" => "Comando encolado con éxito. Esperando firma digital de Jefatura (Nivel 3).", 
            "solicitud_id" => $solicitud_id
        ]);
    } else {
        echo json_encode(["status" => "error", "message" => "Error interno al encolar la acción."]);
    }
} else {
    echo json_encode([
    "status" => "success", 
    "message" => "Solicitud enviada", 
    "command_id" => $lastInsertId 
]);
}
?>