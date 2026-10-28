<div class="container-fluid px-4 mt-4 animate-fade">
    <div class="card mb-4 border-danger shadow">
        <div class="card-header bg-danger text-white d-flex justify-content-between align-items-center py-3">
            <h5 class="mb-0 fw-bold">⚠️ PROTOCOLOS PENDIENTES DE AUTORIZACIÓN</h5>
            <span class="badge bg-white text-danger"><?= count($pendientes) ?> Solicitudes</span>
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr>
                            <th class="ps-3">ID</th>
                            <th>Equipo (Hostname)</th>
                            <th>Acción Solicitada</th>
                            <th>Fecha de Solicitud</th>
                            <th class="text-center">Firma Digital</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($pendientes as $p): ?>
                        <tr>
                            <td class="ps-3 text-muted">#<?= $p['id'] ?></td>
                            <td><span class="badge bg-secondary px-3"><?= htmlspecialchars($p['hostname']) ?></span></td>
                            <td><strong class="text-danger"><?= htmlspecialchars($p['command_type']) ?></strong></td>
                            <td class="small text-muted"><?= $p['created_at'] ?></td>
                            <td class="text-center">
                                <div class="btn-group shadow-sm">
                                    <button class="btn btn-sm btn-success fw-bold px-3" onclick="abrirModalAuth(<?= $p['id'] ?>, '<?= $p['command_type'] ?>')">🔑 VALIDAR</button>
                                    <button class="btn btn-sm btn-outline-danger px-3" onclick="cancelarProtocolo(<?= $p['id'] ?>)">✖ RECHAZAR</button>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                        <?php if(empty($pendientes)): ?>
                        <tr>
                            <td colspan="5" class="text-center py-5">
                                <div class="text-muted">
                                    <p class="mb-0">✅ No hay acciones críticas esperando su firma.</p>
                                    <small>El sistema se encuentra operando bajo parámetros normales.</small>
                                </div>
                            </td>
                        </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="authModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-sm modal-dialog-centered">
        <div class="modal-content border-danger shadow-lg">
            <div class="modal-header bg-danger text-white border-0">
                <h5 class="modal-title fw-bold">Confirmar Acción</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body text-center py-4">
                <p class="text-muted small mb-1">Autorizando protocolo:</p>
                <h4 id="lblProtocolo" class="text-danger fw-bold mb-4">---</h4>
                
                <input type="hidden" id="authCommandId">
                <label class="small fw-bold text-muted mb-2">CÓDIGO DE MICROSOFT AUTHENTICATOR</label>
                <input type="text" class="form-control totp-input mb-2" id="totpPin" maxlength="6" placeholder="000000" autocomplete="off">
                <p class="text-muted" style="font-size: 0.7rem;">Ingrese los 6 dígitos de su aplicación móvil</p>
            </div>
            <div class="modal-footer border-0 p-3">
                <button type="button" class="btn btn-danger w-100 py-2 fw-bold" onclick="validarTotpAjax()">LIBERAR PROTOCOLO</button>
            </div>
        </div>
    </div>
</div>