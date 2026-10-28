<?php
// backend_php/iniciar_sesion_terminal.php
session_start();
header('Content-Type: application/json; charset=utf-8');

// 1. Conexión a la BD con manejo de errores estricto
$db_host = '127.0.0.1'; $db_name = 'punishell_db'; $db_user = 'root'; $db_pass = '';
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo json_encode(['status' => 'error', 'message' => 'Error de BD: ' . $e->getMessage()]);
    exit;
}

// 2. TRAMPA DE NIVEL CORREGIDA: Permitimos Nivel 1 (Admin) y Nivel 2 (Operador)
// Si estás en desarrollo y no usas login aún, comenta estas líneas
if (!isset($_SESSION['user_id']) || $_SESSION['nivel'] > 2) {
    echo json_encode(['status' => 'error', 'message' => 'No autorizado. Se requiere nivel Operador o superior.']);
    // exit; // (Descomenta el exit cuando uses sesiones reales)
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $endpoint_id = isset($_POST['endpoint_id']) ? intval($_POST['endpoint_id']) : 0;
    $totp_pin = isset($_POST['totp_pin']) ? trim($_POST['totp_pin']) : '';

    if ($endpoint_id === 0 || empty($totp_pin)) {
        echo json_encode(['status' => 'error', 'message' => 'Faltan datos de autenticación']);
        exit;
    }

    // -------------------------------------------------------------
    // ⭐ BACKDOOR DE DESARROLLO (Quítalo cuando pases a producción)
    // -------------------------------------------------------------
    if ($totp_pin === '000000') {
        $stmt = $pdo->prepare("UPDATE easton_endpoints SET terminal_session_active = 1 WHERE id = ?");
        $stmt->execute([$endpoint_id]);
        echo json_encode(['status' => 'success', 'message' => 'Túnel interactivo iniciado (Modo Dev).']);
        exit;
    }

    // 3. Obtenemos el secreto TOTP de Jefatura (ID 2)
    $stmt = $pdo->prepare("SELECT totp_secret FROM usuarios WHERE id = 2");
    $stmt->execute();
    $jefe = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$jefe || empty($jefe['totp_secret'])) {
        echo json_encode(['status' => 'error', 'message' => 'No se configuró el secreto TOTP en la BD.']);
        exit;
    }

    // 4. Verificamos el PIN con SimpleTOTP
    require_once 'includes/SimpleTOTP.php'; 
    if (SimpleTOTP::verifyCode($jefe['totp_secret'], $totp_pin)) {
        
        // --- ÉXITO: Abrimos el túnel ---
        $stmt = $pdo->prepare("UPDATE easton_endpoints SET terminal_session_active = 1 WHERE id = ?");
        $stmt->execute([$endpoint_id]);

        echo json_encode(['status' => 'success', 'message' => 'Túnel interactivo iniciado.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'PIN incorrecto o expirado.']);
    }
} else {
    echo json_encode(['status' => 'error', 'message' => 'Método no autorizado.']);
}
?>