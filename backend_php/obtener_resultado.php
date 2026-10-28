<?php
// backend_php/obtener_resultado.php
header('Content-Type: application/json; charset=utf-8');
$conn = new mysqli("127.0.0.1", "root", "", "punishell_db");

if ($conn->connect_error) {
    echo json_encode(['status' => 'error', 'message' => 'Falla de conexión']);
    exit;
}

if (!isset($_GET['id'])) {
    echo json_encode(['status' => 'error', 'message' => 'Falta ID de comando']);
    exit;
}

$id = intval($_GET['id']);

// CORRECCIÓN: Seleccionamos 'output' (no command_output) y 'status'
$stmt = $conn->prepare("SELECT output, status FROM endpoint_commands WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();

if ($row) {
    // mb_convert_encoding evita que el JSON se rompa si hay caracteres raros de Windows
    $output_limpio = mb_convert_encoding($row['output'], "UTF-8", "auto");
    echo json_encode([
        'output' => $output_limpio, 
        'status' => $row['status']
    ]);
} else {
    echo json_encode(['output' => null, 'status' => 'not_found']);
}

$stmt->close();
$conn->close();
?>