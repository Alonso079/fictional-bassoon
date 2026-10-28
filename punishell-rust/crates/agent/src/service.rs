//! Integración con Service Control Manager. Un único servicio y una única instancia.
use crate::runtime::{self, Agent};
use std::{
    ffi::OsString,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const NAME: &str = "PuniShellAgent";
define_windows_service!(ffi_service_main, service_main);
pub fn start() -> windows_service::Result<()> {
    service_dispatcher::start(NAME, ffi_service_main)
}
pub fn install(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = runtime::read_config(config_path)?;
    let exe = std::env::current_exe()?;
    if exe != config.installed_executable
        || config_path != exe.parent().ok_or("ruta de ejecutable")?.join("agent.json")
    {
        return Err("instalar desde la ruta final, con agent.json junto al EXE".into());
    }
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = ServiceInfo {
        name: OsString::from(NAME),
        display_name: OsString::from("PuniShell Agent"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service =
        manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    service.set_description("Agente de inventario y acceso aprobado PuniShell")?;
    service.start::<&str>(&[])?;
    Ok(())
}
fn service_main(_args: Vec<OsString>) {
    if let Err(error) = worker() {
        let path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("service-error.log")));
        if let Some(path) = path {
            let _ = std::fs::write(path, error.to_string());
        }
    }
}
fn worker() -> Result<(), Box<dyn std::error::Error>> {
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    let handler = move |event| match event {
        ServiceControl::Stop => {
            signal.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(NAME, handler)?;
    let status = |state, accepted| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
    ))?;
    let config_path = std::env::current_exe()?
        .parent()
        .ok_or("ejecutable sin carpeta")?
        .join("agent.json");
    let config = runtime::read_config(&config_path)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let agent = rt.block_on(Agent::open(config))?;
    handle.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP))?;
    let result = rt.block_on(agent.run(config_path, stop, false));
    handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))?;
    result?;
    Ok(())
}
