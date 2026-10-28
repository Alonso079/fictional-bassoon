<?php
// backend_php/verificar_sesion.php
header('Content-Type: application/json');

// 1. Conexión
$conn = new mysqli("127.0.0.1", "root", "", "punishell_db");

if ($conn->connect_error) {
    die(json_encode(['session_active' => false, 'error' => 'DB Error']));
}

$id = intval($_GET['endpoint_id'] ?? 0);

if ($id > 0) {
    // 2. LA MAGIA: Le preguntamos a MySQL si (Ahora < FechaExpiracion)
    // Usamos (terminal_expires_at > NOW()) para que sea MySQL quien compare
    $sql = "SELECT terminal_session_active, 
                   terminal_expires_at, 
                   (terminal_expires_at > NOW()) as es_valido 
            FROM easton_endpoints 
            WHERE id = $id";
            
    $res = $conn->query($sql);
    $row = $res->fetch_assoc();

    $session_active = false;

    // Si la sesión está marcada como activa Y el tiempo de la DB dice que es válido...
    if ($row && $row['terminal_session_active'] == 1 && $row['es_valido'] == 1) {
        $session_active = true;
    } else {
        // Si el tiempo ya pasó (es_valido = 0), nos aseguramos de cerrar el bit en la BD
        if ($row && $row['terminal_session_active'] == 1) {
            $conn->query("UPDATE easton_endpoints SET terminal_session_active = 0 WHERE id = $id");
        }
        $session_active = false;
    }

    echo json_encode([
        'session_active' => $session_active,
        'expires_at' => $row['terminal_expires_at'] ?? null,
        'debug_db_now' => date("Y-m-d H:i:s") // Solo para que tú veas qué hora tiene PHP
    ]);
} else {
    echo json_encode(['session_active' => false]);
}
?>