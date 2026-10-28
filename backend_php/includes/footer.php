<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

<script>
    let manageModal;
    let checkOutputInterval;

    // Inicializar el modal al cargar la página
    window.addEventListener('load', function() {
        const mEl = document.getElementById('manageModal');
        if(mEl) manageModal = new bootstrap.Modal(mEl);
    });

    // =========================================================
    // MODO 1: GESTIONAR (Botón Azul/Amarillo)
    // =========================================================
    function openModal(id, hostname) {
        document.getElementById('modalEndpointId').value = id;
        document.getElementById('modalHostName').innerText = hostname;
        
        // 1. Mostramos los controles de Gestión y el Footer
        document.getElementById('caja-gestionar').style.display = 'block';
        // Usamos 'flex' porque los modales de Bootstrap usan flexbox para alinear los botones
        document.getElementById('caja-footer-gestionar').style.display = 'flex';

        // 2. Dibujamos el arte ASCII estático en la pantalla negra
        const termBody = document.getElementById('contenedor-pantalla-negra');
        termBody.innerHTML = `
            <div class="ascii-art">
    ____              _  _____ __          ____
   / __ \\__  ______  (_)/ ___// /_  ___  / / /
  / /_/ / / / / __ \\/ / \\__ \\/ __ \\/ _ \\/ / / 
 / ____/ /_/ / / / / / ___/ / / / /  __/ / /  
/_/    \\__,_|_| /_/_/ /____/_/ /_/\\___/_/_/   
            </div>
            <div class="mb-2">
                <span class="text-purple">Estableciendo túnel con </span>
                <span class="text-cyan">${hostname}</span>
            </div>
            <div class="text-muted-terminal mb-3">PuniShell v2.1 | Encryption: AES-256 | Auth: RBAC Mode</div>

            <div class="terminal-prompt-line d-flex">
                <span class="prompt-path text-success fw-bold me-2">punishell@${hostname}:~$</span>
                <input type="text" id="commandStringInput" value="calc.exe" class="flex-grow-1 bg-transparent border-0 text-white outline-none" style="outline:none; font-family: 'Consolas', monospace;" autocomplete="off" readonly>
            </div>
        `;

        if(manageModal) manageModal.show();
    }

    // =========================================================
    // MODO 2: TERMINAL INTERACTIVA (Botón Negro)
    // =========================================================
    function abrirTerminalInteractiva(id, hostname) {
        document.getElementById('modalEndpointId').value = id;
        document.getElementById('modalHostName').innerText = hostname + " [LIVE]";
        
        document.getElementById('caja-gestionar').style.display = 'none';
        document.getElementById('caja-footer-gestionar').style.display = 'none';
        
        const termBody = document.getElementById('contenedor-pantalla-negra');
        
        // --- INYECCIÓN DE DISEÑO CON CARÁCTER ---
        termBody.innerHTML = `
            <div class="ascii-art" style="color: #ff5555; line-height: 1.2; margin-bottom: 15px; font-size: 12px;">
    ____              _  _____ __          ____
   / __ \\__  ______  (_)/ ___// /_  ___  / / /
  / /_/ / / / / __ \\/ / \\__ \\/ __ \\/ _ \\/ / / 
 / ____/ /_/ / / / / / ___/ / / / /  __/ / /  
/_/    \\__,_|_| /_/_/ /____/_/ /_/\\___/_/_/   
            </div>
            <div class="mb-2" style="font-family: 'Consolas', monospace;">
                <span style="color: #bd93f9;">Estableciendo túnel con </span>
                <span style="color: #8be9fd;">${hostname}</span>
            </div>
            <div style="color: #6272a4; font-size: 0.8rem; margin-bottom: 15px; font-family: 'Consolas', monospace;">
                PuniShell v2.1 | Encryption: AES-256 | Auth: RBAC Mode
            </div>
            
            <div id="term-output" class="mb-2" style="font-family: 'Consolas', monospace; font-size: 14px; color: #f8f8f2;">
                <div style="color: #f1fa8c;"> > [SISTEMA] Verificando estado del túnel seguro...</div>
            </div>

            <div class="terminal-input-line d-flex mt-2">
                <span style="color: #50fa7b; font-weight: bold;" class="me-2">punishell@${hostname}:~$</span>
                <input type="text" id="puttyInput" class="flex-grow-1 bg-transparent border-0 outline-none" 
                       style="color: #f8f8f2; outline: none; font-family: 'Consolas', monospace;" autocomplete="off" disabled>
            </div>
        `;

        if(manageModal) manageModal.show();

        // --- LÓGICA DE VERIFICACIÓN (Mantenida intacta) ---
        fetch(`verificar_sesion.php?endpoint_id=${id}`)
        .then(res => res.json())
        .then(data => {
            if (data.session_active) {
                // Pasamos el hostname para que el prompt sea real
                iniciarModoPutty(hostname);
            } else {
                if (confirm("🔐 ACCESO DENEGADO (ZERO TRUST)\n\nSe requiere autorización de Jefatura por 30 minutos.\n¿Enviar solicitud de acceso ahora?")) {
                    
                    const termOutput = document.getElementById('term-output');
                    termOutput.innerHTML += `<div style="color: #ffb86c;"> > [SISTEMA] Solicitud enviada. Esperando firma del Jefe...</div>`;
                    
                    let formData = new FormData();
                    formData.append('endpoint_id', id);
                    formData.append('command_type', 'open_tunnel');
                    formData.append('command_string', '[SOLICITUD: ACCESO TERMINAL 30 MIN]');

                    fetch('solicitar_accion.php', { method: 'POST', body: formData })
                    .then(r => r.json())
                    .then(res => {
                        if (res.status === 'success') {
                            esperarAprobacion(id, hostname);
                        } else {
                            alert("Error: " + res.message);
                        }
                    });
                }
            }
        });
    }

    // NUEVA FUNCIÓN: Se queda escuchando hasta que el Jefe autorice
    function esperarAprobacion(id, hostname) {
        const output = document.getElementById('term-output');
        
        const checkInterval = setInterval(() => {
            fetch(`verificar_sesion.php?endpoint_id=${id}`)
            .then(res => res.json())
            .then(data => {
                if (data.session_active) {
                    // ¡EL JEFE YA AUTORIZÓ! 
                    clearInterval(checkInterval); // Dejamos de preguntar
                    output.innerHTML += `<div class="text-success"> > [SISTEMA] ¡AUTORIZACIÓN RECIBIDA! Iniciando túnel...</div>`;
                    iniciarModoPutty(); // Abrimos la terminal
                }
            });
        }, 2000); // Preguntamos cada 2 segundos

        // Si el usuario cierra el modal, dejamos de preguntar
        document.getElementById('manageModal').addEventListener('hidden.bs.modal', () => {
            clearInterval(checkInterval);
        }, { once: true });
    }

    // =========================================================
    // MOTOR DE EJECUCIÓN INTERACTIVO
    // =========================================================
    function iniciarModoPutty(hostname = 'easton') {
        const output = document.getElementById('term-output');
        const input = document.getElementById('puttyInput');
        
        // Cambio visual: Usamos el Cian neón de PuniShell
        output.innerHTML += `<div style="color: #8be9fd;"> > [SISTEMA] TÚNEL ESTABLECIDO. Terminal lista.</div>`;
        
        input.disabled = false;
        input.style.color = "#50fa7b"; // Tu escritura será verde neón
        input.focus();

        input.onkeydown = function(e) {
            if (e.key === 'Enter') {
                const cmd = input.value.trim();
                if (!cmd) return;

                // --- Look PuniShell: Prompt verde neón y comando en blanco hueso ---
                output.innerHTML += `<div><span style="color: #50fa7b; font-weight: bold;">punishell@${hostname}:~$</span> <span style="color: #f8f8f2;">${cmd}</span></div>`;
                
                input.value = "";
                input.disabled = true;

                let formData = new FormData();
                formData.append('endpoint_id', document.getElementById('modalEndpointId').value);
                formData.append('command', cmd);

                // --- Mantenemos tu lógica de Fetch intacta ---
                fetch('ejecutar_directo.php', { method: 'POST', body: formData })
                .then(r => r.text()) 
                .then(text => {
                    try {
                        const data = JSON.parse(text);
                        if(data.command_id) {
                            escucharAgente(data.command_id);
                        } else {
                            // Error en color Naranja/Amarillo (Warning)
                            output.innerHTML += `<div style="color: #ffb86c;">[!] Rechazado por servidor: ${data.message || 'Razón desconocida'}</div>`;
                            input.disabled = false;
                            input.focus();
                        }
                    } catch(err) {
                        console.error("Respuesta cruda del servidor:", text);
                        // Error en color Rojo PuniShell
                        output.innerHTML += `<div style="color: #ff5555;">[!] Falla Crítica DB/PHP: ${text}</div>`;
                        input.disabled = false;
                        input.focus();
                    }
                }).catch(err => {
                    output.innerHTML += `<div style="color: #ff5555;">[!] Error de red: ${err.message}</div>`;
                    input.disabled = false;
                    input.focus();
                });
            }
        };
    }

    // =========================================================
    // LISTENER DE RESULTADOS (POLLING)
    // =========================================================
    function escucharAgente(commandId) {
        const output = document.getElementById('term-output');
        const termContainer = document.querySelector('.terminal-body');
        const input = document.getElementById('puttyInput');

        if(checkOutputInterval) clearInterval(checkOutputInterval);

        let pre = document.createElement('pre');
        pre.id = "stream-box-" + commandId;
        pre.className = "text-white mt-1 mb-3";
        pre.style.fontFamily = "'Consolas', monospace";
        pre.style.whiteSpace = "pre-wrap"; 
        output.appendChild(pre);

        checkOutputInterval = setInterval(() => {
            fetch(`obtener_resultado.php?id=${commandId}`)
            .then(res => res.json())
            .then(data => {
                if(data.output !== null && data.output !== undefined) {
                    pre.innerText = data.output;
                    termContainer.scrollTop = termContainer.scrollHeight;
                }

                if(data.status === 'executed') {
                    clearInterval(checkOutputInterval);
                    input.disabled = false;
                    input.focus();
                    console.log(`Comando ${commandId} finalizado.`);
                }
            })
            .catch(err => {
                console.error("Error en el polling:", err);
            });
        }, 1000); 
    }

    // =========================================================
    // SINCRONIZADOR VISUAL (Dropdown -> Pantalla Negra)
    // =========================================================
    function updateCommandString() {
        const select = document.getElementById('commandTypeSelect');
        const input = document.getElementById('commandStringInput');
        
        if (!select || !input) return;

        // Cambiamos el texto verde según lo que elijas
        switch (select.value) {
            case 'test':
                input.value = 'calc.exe';
                input.readOnly = true;
                break;
            case 'lock':
                input.value = 'rundll32.exe user32.dll,LockWorkStation';
                input.readOnly = true;
                break;
            case 'shutdown':
                input.value = 'shutdown /s /f /t 0';
                input.readOnly = true;
                break;
            case 'custom':
                input.value = '';
                input.readOnly = false; // Permite escribir a mano
                input.focus();
                break;
            case 'take_photo':
                input.value = '[COMANDO INTERNO: STEALTH WEBCAM]';
                input.readOnly = true;
                break;
            case 'bitlocker':
                input.value = '[COMANDO INTERNO: EXTRAER RECOVERY KEY]';
                input.readOnly = true;
                break;
            case 'killbill':
                input.value = '[ALERTA: PROTOCOLO NUCLEAR ACTIVADO]';
                input.readOnly = true;
                break;
            default:
                input.value = '';
        }
    }

    // =========================================================
    // DISPARADOR DEL PAYLOAD (Botón Rojo)
    // =========================================================
    function enviarComandoAjax() {
        const endpointId = document.getElementById('modalEndpointId').value;
        const commandType = document.getElementById('commandTypeSelect').value;
        const commandString = document.getElementById('commandStringInput').value;

        if (!commandString) {
            alert("Por favor, ingrese o seleccione un comando válido.");
            return;
        }

        let formData = new FormData();
        formData.append('endpoint_id', endpointId);
        formData.append('command_type', commandType);
        formData.append('command_string', commandString);

        // PON AQUÍ EL NOMBRE REAL DE TU ARCHIVO PHP
        const archivoPhp = 'solicitar_accion.php'; 

        fetch(archivoPhp, {
            method: 'POST',
            body: formData
        })
        .then(res => {
            if (!res.ok) throw new Error("Error HTTP: " + res.status + " (Probablemente el archivo " + archivoPhp + " no existe)");
            return res.text();
        })
        .then(text => {
            try {
                const data = JSON.parse(text);
                if (data.status === 'success') {
                    alert("Payload encolado exitosamente. El agente lo ejecutará pronto.");
                    if(manageModal) manageModal.hide();
                    location.reload(); 
                } else {
                    alert("Error al enviar: " + data.message);
                }
            } catch (e) {
                console.error("Respuesta rota del servidor:", text);
                alert("El servidor PHP falló. Presiona F12 y mira la consola para ver el error real.");
            }
        })
        .catch(err => {
            console.error(err);
            alert(err.message);
        });
    }
    // =========================================================
    // JEFATURA (NIVEL 3): FLUJO DE APROBACIÓN CON MODAL
    // =========================================================
    
    let authModal;
    window.addEventListener('load', function() {
        const aEl = document.getElementById('authModal');
        if(aEl) authModal = new bootstrap.Modal(aEl);
    });

    // 1. Botón Verde: Abre tu Modal de PIN
    function abrirModalAuth(commandId, commandType) {
        document.getElementById('authCommandId').value = commandId;
        document.getElementById('lblProtocolo').innerText = commandType.toUpperCase();
        document.getElementById('totpPin').value = ""; // Limpia el input
        
        if (authModal) authModal.show();
        
        // Auto-focus en el input después de que se abra el modal
        setTimeout(() => document.getElementById('totpPin').focus(), 500);
    }

    // 2. Botón Rojo (Dentro del Modal): Envía el PIN para aprobar
    function validarTotpAjax() {
        const commandId = document.getElementById('authCommandId').value;
        const pin = document.getElementById('totpPin').value.trim();

        if (pin.length < 6) {
            alert("Por favor, ingrese un PIN válido de 6 dígitos.");
            return;
        }

        let formData = new FormData();
        formData.append('command_id', commandId);
        formData.append('status', 'approved');
        formData.append('totp_pin', pin);

        fetch('autorizar_accion.php', { method: 'POST', body: formData })
        .then(res => res.text())
        .then(text => {
            try {
                const data = JSON.parse(text);
                if (data.status === 'success') {
                    if (authModal) authModal.hide();
                    location.reload(); // Recarga para quitar de la lista
                } else {
                    alert("❌ Error: " + data.message);
                    document.getElementById('totpPin').value = "";
                    document.getElementById('totpPin').focus();
                }
            } catch(err) {
                console.error("Error del servidor:", text);
                alert("Error crítico al validar el PIN.");
            }
        })
        .catch(err => alert("Error de red: " + err.message));
    }

    // 3. Botón "RECHAZAR" (Rechaza directamente sin pedir PIN)
    function cancelarProtocolo(commandId) {
        if (!confirm("⚠️ ¿Estás seguro de que deseas RECHAZAR y cancelar este protocolo?")) return;

        let formData = new FormData();
        formData.append('command_id', commandId);
        formData.append('status', 'rejected');

        fetch('autorizar_accion.php', { method: 'POST', body: formData })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                location.reload();
            } else {
                alert("Error al rechazar: " + data.message);
            }
        })
        .catch(err => alert("Error de red al rechazar."));
    }
</script>