<?php
// backend_php/poll.php

header('Content-Type: application/json; charset=utf-8');

$db_host = '127.0.0.1';
$db_name = 'punishell_db';
$db_user = 'root';
$db_pass = ''; 

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    // Modo estricto para ver errores si algo falla
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Error BD']);
    exit;
}

// ---------------------------------------------------------
// ESCENARIO 1: EL AGENTE ESTÁ RESPONDIENDO A UN COMANDO (Notificando Fin)
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_command') {
    
    $cmd_id = $_POST['command_id'] ?? null;
    $status = $_POST['status'] ?? 'executed';
    $mac_address = $_POST['mac_address'] ?? null;
    
    if ($cmd_id) {
        try {
            // CORRECCIÓN CRÍTICA: Usamos updated_at en lugar de executed_at
            $stmtCmd = $pdo->prepare("UPDATE endpoint_commands SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
            $stmtCmd->execute([$status, $cmd_id]);
        } catch (Exception $e) {
            // Si la columna no existe, hacemos un update básico sin el timestamp
            $stmtCmd = $pdo->prepare("UPDATE endpoint_commands SET status = ? WHERE id = ?");
            $stmtCmd->execute([$status, $cmd_id]);
        }
    }

    if (isset($_POST['recovery_key']) && !empty($_POST['recovery_key']) && $mac_address) {
        $recovery_key = trim($_POST['recovery_key']);
        $stmtKey = $pdo->prepare("UPDATE easton_endpoints SET bitlocker_recovery_key = ? WHERE mac_address = ?");
        $stmtKey->execute([$recovery_key, $mac_address]);
    }

    if (isset($_POST['webcam_image_b64']) && !empty($_POST['webcam_image_b64']) && $mac_address) {
        $image_b64 = $_POST['webcam_image_b64'];
        $binary_image = base64_decode($image_b64);
        if ($binary_image) {
            $stmtImg = $pdo->prepare("UPDATE easton_endpoints SET last_webcam_shot = ? WHERE mac_address = ?");
            $stmtImg->execute([$binary_image, $mac_address]);
        }
    }

    echo json_encode(['status' => 'success', 'message' => 'Comando finalizado correctamente']);
    exit;
}

// ---------------------------------------------------------
// ESCENARIO 2: EL AGENTE ESTÁ HACIENDO SU CHECK-IN REGULAR
// ---------------------------------------------------------

$json_data = file_get_contents('php://input');
$agent_data = json_decode($json_data, true);

if (!$agent_data || !isset($agent_data['bios_serial'])) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Payload invalido']);
    exit;
}

// Recopilación de variables
$hostname = $agent_data['hostname'] ?? 'UNKNOWN';
$local_ip = $agent_data['local_ip'] ?? 'UNKNOWN';
$public_ip = $agent_data['public_ip'] ?? 'UNKNOWN';
$mac_address = $agent_data['mac_address'] ?? 'UNKNOWN';
$bios_serial = $agent_data['bios_serial'];
$ssid = $agent_data['ssid'] ?? 'UNKNOWN';
$bssid = $agent_data['bssid'] ?? 'UNKNOWN';
$logged_user = $agent_data['logged_user'] ?? 'UNKNOWN';
$os_version = $agent_data['os_version'] ?? 'UNKNOWN';
$uptime_hours = $agent_data['uptime_hours'] ?? 0;
$disk_free_gb = $agent_data['disk_free_gb'] ?? 0;
$ram_gb = $agent_data['ram_gb'] ?? 0;
$bitlocker_status = $agent_data['bitlocker_status'] ?? 'UNKNOWN';
$defender_status = $agent_data['defender_status'] ?? 'UNKNOWN';

$latitude = $agent_data['latitude'] ?? 'UNKNOWN';
$longitude = $agent_data['longitude'] ?? 'UNKNOWN';

// Guardamos en la base de datos
$stmt = $pdo->prepare("
    INSERT INTO easton_endpoints 
    (hostname, local_ip, public_ip, latitude, longitude, mac_address, bios_serial, ssid, bssid, logged_user, os_version, uptime_hours, disk_free_gb, ram_gb, bitlocker_status, defender_status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE 
        hostname = VALUES(hostname), local_ip = VALUES(local_ip), public_ip = VALUES(public_ip),
        latitude = VALUES(latitude), longitude = VALUES(longitude), mac_address = VALUES(mac_address),
        ssid = VALUES(ssid), bssid = VALUES(bssid), logged_user = VALUES(logged_user),
        os_version = VALUES(os_version), uptime_hours = VALUES(uptime_hours), disk_free_gb = VALUES(disk_free_gb),
        ram_gb = VALUES(ram_gb), bitlocker_status = VALUES(bitlocker_status), defender_status = VALUES(defender_status),
        last_seen = CURRENT_TIMESTAMP
");
$stmt->execute([
    $hostname, $local_ip, $public_ip, $latitude, $longitude, $mac_address, $bios_serial, 
    $ssid, $bssid, $logged_user, $os_version, $uptime_hours, 
    $disk_free_gb, $ram_gb, $bitlocker_status, $defender_status
]);

// --- BUSCAMOS EL ID Y EL ESTADO DEL TÚNEL (Con validación de nulos) ---
$stmt = $pdo->prepare("SELECT id, terminal_session_active FROM easton_endpoints WHERE bios_serial = ?");
$stmt->execute([$bios_serial]);
$endpoint = $stmt->fetch(PDO::FETCH_ASSOC);

$endpoint_id = $endpoint['id'] ?? null;
$terminal_live = $endpoint['terminal_session_active'] ?? 0;

// Buscamos comandos pendientes SOLO si tenemos el ID
$approved_commands = [];
if ($endpoint_id) {
    $stmt = $pdo->prepare("SELECT id, command_string FROM endpoint_commands WHERE endpoint_id = ? AND status = 'approved'");
    $stmt->execute([$endpoint_id]);
    $approved_commands = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// --- RESPUESTA FINAL AL AGENTE ---
echo json_encode([
    'status' => 'success',
    'terminal_live' => (int)$terminal_live, // El interruptor del Turbo
    'pending_commands' => $approved_commands
]);
?>