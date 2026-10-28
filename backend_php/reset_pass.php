<?php
// backend_php/reset_pass.php
$db_host = '127.0.0.1';
$db_name = 'punishell_db';
$db_user = 'root';
$db_pass = ''; 

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    
    // Generamos el hash REAL y criptográficamente válido
    $hash_real = password_hash('Easton2026', PASSWORD_DEFAULT);
    
    // Lo inyectamos en la base de datos para ti y para Don Claudio
    $stmt = $pdo->prepare("UPDATE usuarios SET password_hash = ? WHERE id IN (1, 2)");
    $stmt->execute([$hash_real]);
    
    echo "<h2>¡Candados actualizados!</h2>";
    echo "<p>El hash real es: <br><small>" . $hash_real . "</small></p>";
    echo "<a href='login.php'>Ir al Login ahora sí</a>";
    
} catch (PDOException $e) {
    die("Error: " . $e->getMessage());
}
?>