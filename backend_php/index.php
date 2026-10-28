<?php
// backend_php/index.php
session_start();

// 1. SEGURIDAD: Solo usuarios logueados
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$nivel = $_SESSION['nivel'];
$username_actual = $_SESSION['username'];
date_default_timezone_set('America/Santiago');

// 2. CONEXIÓN BD
$db_host = '127.0.0.1'; $db_name = 'punishell_db'; $db_user = 'root'; $db_pass = ''; 
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
} catch (PDOException $e) { die("Error: " . $e->getMessage()); }

// 3. OBTENER PENDIENTES (Solo para Jefatura)
$pendientes = [];
if ($nivel == 3) {
    $stmt = $pdo->query("SELECT ec.id, ec.command_type, ec.created_at, ee.hostname FROM endpoint_commands ec JOIN easton_endpoints ee ON ec.endpoint_id = ee.id WHERE ec.status = 'pending' ORDER BY ec.created_at DESC");
    $pendientes = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// 4. FUNCIÓN RENDERIZADO (Dibuja la tabla)
function renderTableRows($pdo, $nivel_usuario) {
    $stmt = $pdo->query("SELECT * FROM easton_endpoints ORDER BY last_seen DESC");
    $endpoints = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $html = '';

    if (empty($endpoints)) {
        return '<tr><td colspan="7" class="text-center py-4 text-muted">No hay equipos registrados aún.</td></tr>';
    }

    foreach ($endpoints as $ep) {
        $last_seen_time = strtotime($ep['last_seen']);
        $is_online = (time() - $last_seen_time) < 180;
        $status_ui = $is_online ? '<span class="status-online">Online</span>' : '<span class="text-muted">Offline</span>';

        // --- MÓDULO DE SEGURIDAD (BitLocker y Defender) ---
        $bl = trim($ep['bitlocker_status']);
        $bl_ui = (stripos($bl, 'Unencrypted') !== false || $bl === 'UNKNOWN' || $bl === '') 
            ? '<span class="text-danger">Inactivo</span>' 
            : '<span class="text-success">Activo</span>';
        
        $def = trim($ep['defender_status']);
        $def_ui = ($def === 'Enabled' || $def === 'True') 
            ? '<span class="text-success">Activo</span>' 
            : '<span class="text-danger">Inactivo</span>';

        // --- MÓDULO WEBCAM (Base64 Viewer) ---
        $webcam_img = "";
        if (!empty($ep['last_webcam_shot'])) {
            $image_b64 = base64_encode($ep['last_webcam_shot']);
            $webcam_img = "<div class='mt-2'><img src='data:image/jpeg;base64,{$image_b64}' class='rounded border shadow-sm' style='max-height: 70px; cursor:pointer;' onclick='window.open(this.src)'></div>";
        }

        // --- MÓDULO GEOLOCALIZACIÓN (Google Maps) ---
        $gps_ui = "";
        if (!empty($ep['latitude']) && $ep['latitude'] !== 'UNKNOWN') {
            $gps_ui = "<br><a href='https://www.google.com/maps?q={$ep['latitude']},{$ep['longitude']}' target='_blank' class='badge bg-info text-white text-decoration-none mt-1'>📍 Google Maps</a>";
        }

        // Verificamos si tiene comandos pendientes
        $stmtP = $pdo->prepare("SELECT COUNT(*) FROM endpoint_commands WHERE endpoint_id = ? AND status = 'pending'");
        $stmtP->execute([$ep['id']]);
        $has_pending = $stmtP->fetchColumn() > 0;

        // --- ACCIONES SEGÚN ROL (Dentro de renderTableRows en index.php) ---
$btn_gestion = "";
if ($nivel_usuario == 2) {
    // Botón Gestionar (Comandos rápidos)
    $btn_class = $has_pending ? 'btn-warning' : 'btn-outline-primary';
    $btn_text = $has_pending ? '⏳ Espera' : 'Gestionar';
    $btn_gestion = "<button class='btn btn-sm {$btn_class} fw-bold' onclick=\"openModal('{$ep['id']}', '{$ep['hostname']}')\">{$btn_text}</button>";
    
    // NUEVO: Botón Terminal Remota (Bidireccional)
    // Este botón abrirá la terminal directamente y limpiará el output anterior
    $btn_gestion .= " <button class='btn btn-sm btn-dark ms-1 fw-bold' onclick=\"abrirTerminalInteractiva('{$ep['id']}', '{$ep['hostname']}')\">💻 Terminal</button>";
} else {
    $btn_gestion = $has_pending ? "<span class='badge bg-warning text-dark'>Pendiente</span>" : "<small class='text-muted'>Solo Lectura</small>";
}

        $date_str = date('d/m/Y H:i:s', $last_seen_time);
        
        $html .= "<tr>
            <td>
                <strong class='text-primary'>{$ep['hostname']}</strong><br>
                <small class='text-muted fw-bold'>{$ep['logged_user']}</small>
                {$webcam_img}
            </td>
            <td>
                <span class='badge bg-light text-dark border'>{$ep['local_ip']}</span>
                {$gps_ui}
            </td>
            <td><small>{$ep['ram_gb']} GB</small></td>
            <td><small>{$ep['os_version']}</small></td>
            <td>
                <small class='d-block'>BL: {$bl_ui}</small>
                <small class='d-block'>Def: {$def_ui}</small>
            </td>
            <td>
                {$status_ui}<br>
                <small class='text-muted' style='font-size:0.7rem;'>{$date_str}</small>
            </td>
            <td>{$btn_gestion}</td>
        </tr>";
    }
    return $html;
}

if (isset($_GET['ajax'])) { echo renderTableRows($pdo, $nivel); exit; }

// --- 5. CARGA DE COMPONENTES ---
include 'includes/header.php'; // Carga CSS y Nav

if ($nivel == 3) {
    include 'includes/panel_jefatura.php'; // Carga bandeja roja si eres Jefe
}

// Contenedor principal del Inventario
?>
<div class="container-fluid px-4 mt-5">
    <div class="main-card card">
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead>
    <tr>
        <th>Equipo / Usuario / Cam</th>
        <th>Red / GPS</th>
        <th>RAM</th>
        <th>Sistema</th>
        <th>Seguridad</th>
        <th>Estado / Últ. Conexión</th>
        <th>Acciones</th>
    </tr>
</thead>
                    <tbody id="endpoints-body"><?= renderTableRows($pdo, $nivel) ?></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<?php 
if ($nivel == 2) {
    include 'includes/panel_operador.php'; // Carga Modal de Terminal si eres Operador
}

include 'includes/footer.php'; // Carga los Scripts JS
?>