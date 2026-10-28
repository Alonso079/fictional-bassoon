<?php
// backend_php/reportar_resultado.php
header('Content-Type: application/json; charset=utf-8');

$db_host = '127.0.0.1'; $db_name = 'punishell_db'; $db_user = 'root'; $db_pass = '';
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    // Modo estricto para atrapar cualquier error de SQL
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) { 
    die(json_encode(['status' => 'error', 'message' => 'Error DB: ' . $e->getMessage()])); 
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $id = $_POST['id'] ?? null;
    $output = $_POST['output'] ?? '';

    if ($id) {
        try {
            // Quitamos el 'updated_at' que probablemente no existe y rompe todo.
            // Usamos IFNULL por si acaso, aunque ejecutar_directo ya lo manda vacío.
            $stmt = $pdo->prepare("UPDATE endpoint_commands SET output = CONCAT(IFNULL(output, ''), ?) WHERE id = ?");
            $stmt->execute([$output, $id]);
            
            echo json_encode(['status' => 'success']);
        } catch (Exception $e) {
            echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
        }
    } else {
        echo json_encode(['status' => 'error', 'message' => 'ID no proporcionado']);
    }
} else {
    echo json_encode(['status' => 'error', 'message' => 'Método no POST']);
}
?>