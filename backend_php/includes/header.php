<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PUNISHELL MDM | Easton Design</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    
    <style>
        :root {
            --easton-red: #E31D2B;
            --terminal-black: #121212;
        }

        body { 
            background-color: #f0f2f5; 
            color: #1a1d23; 
            font-family: 'Inter', sans-serif;
            background-image: radial-gradient(#d1d9e6 0.8px, transparent 0.8px);
            background-size: 30px 30px;
        }

        /* Navbar elegante */
        .navbar { 
            background: rgba(255, 255, 255, 0.95) !important;
            backdrop-filter: blur(10px);
            border-bottom: 3px solid var(--easton-red);
            padding: 0.8rem 2rem;
        }

        .navbar-brand { font-weight: 800; font-size: 1.4rem; letter-spacing: -0.5px; }
        .brand-red { color: var(--easton-red); }

        /* Card del Inventario */
        .main-card { 
            border: none; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.08);
            background: #fff;
            overflow: hidden;
        }

        .table thead { background-color: #f8f9fa; }
        .table th { font-weight: 700; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; color: #6c757d; padding: 15px; }
        .table td { padding: 15px; vertical-align: middle; border-bottom: 1px solid #f0f0f0; }

        /* --- TERMINAL V3 (High Contrast Edition) --- */
.terminal-window { 
    background-color: #000000; 
    border-radius: 12px; 
    overflow: hidden; 
    box-shadow: 0 25px 50px rgba(0,0,0,0.6);
    border: 1px solid #444; /* Borde más visible */
}

.terminal-header { 
    background: #1a1a1a; 
    padding: 12px 18px;
    border-bottom: 1px solid #333;
}

.terminal-body { 
    padding: 35px; 
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    background-color: #000000; /* Fondo negro puro para máximo contraste */
    min-height: 400px;
}

/* Mejora de contraste para textos oscuros */
.ascii-art { 
    color: #ff3e3e; /* Rojo más vibrante */
    font-size: 11px; 
    line-height: 1.1; 
    margin-bottom: 25px; 
    text-shadow: 0 0 10px rgba(255, 62, 62, 0.3);
    white-space: pre; /* Vital para que no se desordene */
}

.text-purple { color: #bd93f9 !important; font-weight: bold; } /* Morado más brillante */
.text-cyan { color: #8be9fd !important; font-weight: bold; }   /* Cyan eléctrico */
.text-muted-terminal { color: #a9a9a9 !important; font-size: 0.85rem; } /* Reemplazo para el gris oscuro */

#commandStringInput { 
    background: transparent !important; 
    border: none !important; 
    color: #50fa7b !important; /* Verde Neón */
    outline: none !important; 
    width: 100%; 
    font-family: inherit;
    font-size: 16px;
    text-shadow: 0 0 5px rgba(80, 250, 123, 0.5);
}

        /* Status Online con Pulso */
        .status-online { color: #198754; font-weight: 700; position: relative; padding-left: 18px; }
        .status-online::before {
            content: ""; position: absolute; left: 0; top: 6px; width: 10px; height: 10px;
            background-color: #198754; border-radius: 50%; animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(25, 135, 84, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(25, 135, 84, 0); }
            100% { box-shadow: 0 0 0 0 rgba(25, 135, 84, 0); }
        }

        .totp-input { text-align: center; font-size: 2.8rem; letter-spacing: 1rem; border: 2px solid var(--easton-red); font-family: 'JetBrains Mono', monospace; color: var(--easton-red); border-radius: 10px; }
    </style>
</head>
<body>

<nav class="navbar navbar-light px-4 py-3 d-flex justify-content-between sticky-top">
    <span class="navbar-brand mb-0">
        <span class="brand-red">EASTON</span>DESIGN
        <span class="fw-light text-muted" style="font-size: 0.9rem; margin-left: 8px;">PUNISHELL MDM</span>
    </span>
    <div class="d-flex align-items-center">
        <div class="text-end me-4 border-end pe-4">
            <span class="badge rounded-pill <?= ($nivel == 3) ? 'bg-danger' : 'bg-dark' ?> px-3 py-2">
                <?= ($nivel == 3) ? 'LEVEL 3: JEFATURA' : 'LEVEL 2: OPERADOR' ?>
            </span>
        </div>
        <div class="ps-2">
            <span class="text-dark fw-bold d-block small"><?= strtoupper($username_actual) ?></span>
            <a href="logout.php" class="text-danger text-decoration-none small fw-bold">SALIR DEL SISTEMA</a>
        </div>
    </div>
</nav>