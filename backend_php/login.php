<?php
// backend_php/login.php
session_start();

// Si ya está logueado, lo mandamos directo al dashboard
if (isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$error = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $db_host = '127.0.0.1';
    $db_name = 'punishell_db';
    $db_user = 'root';
    $db_pass = ''; 

    try {
        $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $username = trim($_POST['username']);
        $password = $_POST['password'];

        $stmt = $pdo->prepare("SELECT id, username, password_hash, nivel FROM usuarios WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Verificamos si el usuario existe y si la contraseña coincide con el hash
        if ($user && password_verify($password, $user['password_hash'])) {
            // ¡Éxito! Creamos las variables de sesión
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['nivel'] = $user['nivel'];

            // Redirigimos al Centro de Mando
            header("Location: index.php");
            exit;
        } else {
            $error = "Usuario o contraseña incorrectos.";
        }
    } catch (PDOException $e) {
        $error = "Error de conexión a la base de datos.";
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acceso | PuniShell MDM</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #1e1e2e; color: #fff; height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-card { background-color: #282a36; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 400px; border-top: 4px solid #E31D2B; }
        .btn-easton { background-color: #E31D2B; color: white; font-weight: bold; transition: 0.3s; }
        .btn-easton:hover { background-color: #c91824; color: white; }
    </style>
</head>
<body>

<div class="login-card">
    <div class="text-center mb-4">
        <h2 class="fw-bold">EASTON DESIGN</h2>
        <p class="text-muted">PuniShell MDM - Acceso Restringido</p>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-danger text-center p-2"><?= $error ?></div>
    <?php endif; ?>

    <form method="POST" action="login.php">
        <div class="mb-3">
            <label class="form-label text-secondary small fw-bold">USUARIO</label>
            <input type="text" name="username" class="form-control bg-dark text-white border-secondary" required autocomplete="off">
        </div>
        <div class="mb-4">
            <label class="form-label text-secondary small fw-bold">CONTRASEÑA</label>
            <input type="password" name="password" class="form-control bg-dark text-white border-secondary" required>
        </div>
        <button type="submit" class="btn btn-easton w-100 py-2">INICIAR SESIÓN</button>
    </form>
</div>

</body>
</html>