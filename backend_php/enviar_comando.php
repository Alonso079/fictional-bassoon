<?php
// backend_php/enviar_comando.php

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die("Acceso denegado.");
}

$db_host = '127.0.0.1';
$db_name = 'punishell_db';
$db_user = 'root';
$db_pass = ''; 

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Error de conexión: " . $e->getMessage());
}

$endpoint_id = $_POST['endpoint_id'] ?? null;
$command_type = $_POST['command_type'] ?? null;
$command_string = $_POST['command_string'] ?? null;

if ($endpoint_id && $command_type && $command_string) {
    $stmt = $pdo->prepare("
        INSERT INTO endpoint_commands (endpoint_id, command_type, command_string, status) 
        VALUES (?, ?, ?, 'pending')
    ");
    $stmt->execute([$endpoint_id, $command_type, $command_string]);
}

// Redirigir de vuelta al dashboard de forma silenciosa e inmediata
header("Location: index.php");
exit;
?>