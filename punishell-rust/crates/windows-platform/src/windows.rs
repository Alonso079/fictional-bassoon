use crate::{PlatformError, Result};
use punishell_protocol::wire::{BitLockerVolume, Inventory, NetworkAdapter, WifiInfo};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::os::windows::ffi::OsStrExt;
use std::{
    collections::HashMap,
    ffi::c_void,
    mem::{size_of, zeroed},
    path::Path,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    NetworkManagement::{IpHelper::*, WiFi::*},
    Networking::WinSock::*,
    Security::{Cryptography::*, WinTrust::*},
    Storage::FileSystem::*,
    System::{
        Environment::*, Registry::*, RemoteDesktop::*, Shutdown::*, SystemInformation::*,
        Threading::*,
    },
};
fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
fn error() -> PlatformError {
    std::io::Error::last_os_error().into()
}
// SAFETY: strings below are allocated/terminated by the specific Windows API
// whose owning buffer stays alive for the call. Limit the scan defensively.
unsafe fn string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while len < 32768 && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
pub fn replace_file(source: &Path, target: &Path) -> Result<()> {
    // SAFETY: NUL terminated paths live throughout MoveFileExW.
    if unsafe {
        MoveFileExW(
            wide(source).as_ptr(),
            wide(target).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(error());
    }
    Ok(())
}
pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
    dpapi(data, false)
}
pub fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
    dpapi(data, true)
}
fn dpapi(data: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    if data.len() > u32::MAX as usize {
        return Err(PlatformError::Other("blob demasiado grande".into()));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { zeroed() };
    // SAFETY: DPAPI accepts input only for reading; output is allocated by LocalAlloc.
    let ok = unsafe {
        if decrypt {
            CryptUnprotectData(
                &input,
                null_mut(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                wide("PuniShell Rust identity").as_ptr(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(error());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as HLOCAL);
    }
    Ok(result)
}
fn hostname() -> Result<String> {
    let mut data = vec![0u16; 256];
    let mut size = data.len() as u32;
    if unsafe { GetComputerNameExW(ComputerNameDnsHostname, data.as_mut_ptr(), &mut size) } == 0 {
        return Err(error());
    }
    Ok(String::from_utf16_lossy(&data[..size as usize]))
}
fn registry(name: &str) -> Result<String> {
    let mut key: HKEY = null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").as_ptr(),
            0,
            KEY_READ,
            &mut key,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    let mut value = vec![0u16; 512];
    let mut len = value.len() as u32 * 2;
    let mut kind = 0;
    let status = unsafe {
        RegQueryValueExW(
            key,
            wide(name).as_ptr(),
            null(),
            &mut kind,
            value.as_mut_ptr().cast(),
            &mut len,
        )
    };
    unsafe {
        RegCloseKey(key);
    }
    if status != 0 || kind != REG_SZ {
        return Err(PlatformError::Other("registro no disponible".into()));
    }
    Ok(
        String::from_utf16_lossy(&value[..(len as usize / 2).min(value.len())])
            .trim_end_matches('\0')
            .into(),
    )
}
fn adapters() -> Result<Vec<NetworkAdapter>> {
    let mut size = 16384u32;
    let mut words = vec![0u64; size as usize / 8];
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // SAFETY: u64 buffer supplies required alignment and byte size. Windows returns
    // linked records within this buffer; it stays alive until all records are copied.
    let mut status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            null(),
            words.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status == ERROR_BUFFER_OVERFLOW {
        if size > 1024 * 1024 {
            return Err(PlatformError::Other("adaptadores demasiado grandes".into()));
        }
        words.resize((size as usize).div_ceil(8), 0);
        status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                null(),
                words.as_mut_ptr().cast(),
                &mut size,
            )
        };
    }
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    let mut result = vec![];
    let mut current: *const IP_ADAPTER_ADDRESSES_LH = words.as_ptr().cast();
    while !current.is_null() && result.len() < 64 {
        let adapter = unsafe { &*current };
        let mut addresses = vec![];
        let mut address = adapter.FirstUnicastAddress;
        while !address.is_null() && addresses.len() < 64 {
            let socket = unsafe { (*address).Address };
            if !socket.lpSockaddr.is_null() {
                let family = unsafe { (*socket.lpSockaddr).sa_family };
                if family == AF_INET && socket.iSockaddrLength as usize >= size_of::<SOCKADDR_IN>()
                {
                    let a = unsafe { &*socket.lpSockaddr.cast::<SOCKADDR_IN>() };
                    addresses.push(
                        std::net::Ipv4Addr::from(unsafe { a.sin_addr.S_un.S_addr }.to_ne_bytes())
                            .to_string(),
                    );
                }
                if family == AF_INET6
                    && socket.iSockaddrLength as usize >= size_of::<SOCKADDR_IN6>()
                {
                    let a = unsafe { &*socket.lpSockaddr.cast::<SOCKADDR_IN6>() };
                    addresses
                        .push(std::net::Ipv6Addr::from(unsafe { a.sin6_addr.u.Byte }).to_string());
                }
            }
            address = unsafe { (*address).Next };
        }
        let mac = if adapter.PhysicalAddressLength == 6 {
            Some(
                adapter.PhysicalAddress[..6]
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            )
        } else {
            None
        };
        result.push(NetworkAdapter {
            name: unsafe { string(adapter.FriendlyName) },
            mac,
            addresses,
            active: adapter.OperStatus == 1,
        });
        current = adapter.Next;
    }
    Ok(result)
}
fn wifi() -> Result<Vec<WifiInfo>> {
    let mut handle: HANDLE = null_mut();
    let mut version = 0;
    let status = unsafe { WlanOpenHandle(2, null(), &mut version, &mut handle) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    let mut list: *mut WLAN_INTERFACE_INFO_LIST = null_mut();
    let status = unsafe { WlanEnumInterfaces(handle, null(), &mut list) };
    if status != 0 {
        unsafe {
            WlanCloseHandle(handle, null());
        }
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    let mut result = vec![];
    for index in 0..unsafe { (*list).dwNumberOfItems }.min(64) {
        let iface = unsafe { &*(*list).InterfaceInfo.as_ptr().add(index as usize) };
        let mut size = 0;
        let mut data: *mut c_void = null_mut();
        let mut kind = 0;
        if unsafe {
            WlanQueryInterface(
                handle,
                &iface.InterfaceGuid,
                wlan_intf_opcode_current_connection,
                null(),
                &mut size,
                &mut data,
                &mut kind,
            )
        } == 0
        {
            if size as usize >= size_of::<WLAN_CONNECTION_ATTRIBUTES>() {
                let attributes = unsafe { &*data.cast::<WLAN_CONNECTION_ATTRIBUTES>() };
                let association = &attributes.wlanAssociationAttributes;
                result.push(WifiInfo {
                    ssid: String::from_utf8_lossy(
                        &association.dot11Ssid.ucSSID
                            [..(association.dot11Ssid.uSSIDLength as usize).min(32)],
                    )
                    .into(),
                    bssid: association
                        .dot11Bssid
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                    signal_percent: association.wlanSignalQuality,
                });
            }
            unsafe {
                WlanFreeMemory(data);
            }
        }
    }
    unsafe {
        WlanFreeMemory(list.cast());
        WlanCloseHandle(handle, null());
    }
    Ok(result)
}
fn users() -> Result<Vec<String>> {
    let mut data: *mut WTS_SESSION_INFOW = null_mut();
    let mut count = 0;
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut data, &mut count) } == 0
    {
        return Err(error());
    }
    let mut result = vec![];
    for index in 0..count.min(64) {
        let session = unsafe { &*data.add(index as usize) };
        if session.State != WTSActive && session.State != WTSDisconnected {
            continue;
        }
        let mut value: *mut u16 = null_mut();
        let mut size = 0;
        if unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session.SessionId,
                WTSUserName,
                &mut value,
                &mut size,
            )
        } != 0
        {
            let name = unsafe { string(value) };
            unsafe {
                WTSFreeMemory(value.cast());
            }
            if !name.is_empty() {
                result.push(name);
            }
        }
    }
    unsafe {
        WTSFreeMemory(data.cast());
    }
    Ok(result)
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Bios {
    serial_number: Option<String>,
}

#[derive(Deserialize)]
#[allow(non_camel_case_types, non_snake_case)]
struct Win32_EncryptableVolume {
    __Path: String,
    DriveLetter: Option<String>,
    ProtectionStatus: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ConversionStatus {
    return_value: u32,
    conversion_status: u32,
    encryption_percentage: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EncryptionMethod {
    return_value: u32,
    encryption_method: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LockStatus {
    return_value: u32,
    lock_status: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AutoUnlockStatus {
    return_value: u32,
    is_auto_unlock_enabled: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MethodResult {
    return_value: u32,
}

fn bitlocker_protection(value: Option<u32>) -> &'static str {
    match value {
        Some(0) => "off",
        Some(1) => "on",
        _ => "unknown",
    }
}

fn bitlocker_conversion(value: u32) -> &'static str {
    match value {
        0 => "fully_decrypted",
        1 => "fully_encrypted",
        2 => "encryption_in_progress",
        3 => "decryption_in_progress",
        4 => "encryption_paused",
        5 => "decryption_paused",
        _ => "unknown",
    }
}

fn bitlocker_method(value: u32) -> &'static str {
    match value {
        0 => "none",
        1 => "aes_128_with_diffuser",
        2 => "aes_256_with_diffuser",
        3 => "aes_128",
        4 => "aes_256",
        5 => "hardware_encryption",
        6 => "xts_aes_128",
        7 => "xts_aes_256",
        _ => "unknown",
    }
}

fn bitlocker_volumes() -> Result<Vec<BitLockerVolume>> {
    let connection =
        wmi::WMIConnection::with_namespace_path("ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption")
            .map_err(|error| PlatformError::Other(error.to_string()))?;
    let volumes: Vec<Win32_EncryptableVolume> = connection
        .raw_query("SELECT __Path,DriveLetter,ProtectionStatus FROM Win32_EncryptableVolume")
        .map_err(|error| PlatformError::Other(error.to_string()))?;
    let mut result = Vec::with_capacity(volumes.len().min(32));
    for volume in volumes.into_iter().take(32) {
        let mut errors = vec![];
        let conversion = match connection
            .exec_instance_method::<Win32_EncryptableVolume, ConversionStatus>(
                &volume.__Path,
                "GetConversionStatus",
                (),
            ) {
            Ok(value) if value.return_value == 0 => Some(value),
            Ok(value) => {
                errors.push(format!("GetConversionStatus={}", value.return_value));
                None
            }
            Err(error) => {
                errors.push(format!("GetConversionStatus: {error}"));
                None
            }
        };
        let method = match connection
            .exec_instance_method::<Win32_EncryptableVolume, EncryptionMethod>(
                &volume.__Path,
                "GetEncryptionMethod",
                (),
            ) {
            Ok(value) if value.return_value == 0 => Some(value.encryption_method),
            Ok(value) => {
                errors.push(format!("GetEncryptionMethod={}", value.return_value));
                None
            }
            Err(error) => {
                errors.push(format!("GetEncryptionMethod: {error}"));
                None
            }
        };
        let lock = match connection.exec_instance_method::<Win32_EncryptableVolume, LockStatus>(
            &volume.__Path,
            "GetLockStatus",
            (),
        ) {
            Ok(value) if value.return_value == 0 => Some(match value.lock_status {
                0 => "unlocked",
                1 => "locked",
                _ => "unknown",
            }),
            Ok(value) => {
                errors.push(format!("GetLockStatus={}", value.return_value));
                None
            }
            Err(error) => {
                errors.push(format!("GetLockStatus: {error}"));
                None
            }
        };
        let auto_unlock = match connection
            .exec_instance_method::<Win32_EncryptableVolume, AutoUnlockStatus>(
                &volume.__Path,
                "IsAutoUnlockEnabled",
                (),
            ) {
            Ok(value) if value.return_value == 0 => Some(value.is_auto_unlock_enabled),
            Ok(value) => {
                errors.push(format!("IsAutoUnlockEnabled={}", value.return_value));
                None
            }
            Err(error) => {
                errors.push(format!("IsAutoUnlockEnabled: {error}"));
                None
            }
        };
        result.push(BitLockerVolume {
            mount_point: volume.DriveLetter,
            protection_status: bitlocker_protection(volume.ProtectionStatus).into(),
            conversion_status: conversion
                .as_ref()
                .map(|value| bitlocker_conversion(value.conversion_status).into()),
            encryption_percentage: conversion
                .as_ref()
                .map(|value| value.encryption_percentage.min(100) as u8),
            encryption_method: method.map(|value| bitlocker_method(value).into()),
            lock_status: lock.map(str::to_owned),
            auto_unlock_enabled: auto_unlock,
            errors,
        });
    }
    Ok(result)
}

pub fn resume_bitlocker_protection(mount_point: &str) -> Result<()> {
    if mount_point.len() != 2
        || !mount_point.as_bytes()[0].is_ascii_uppercase()
        || mount_point.as_bytes()[1] != b':'
    {
        return Err(PlatformError::Other("unidad BitLocker inválida".into()));
    }
    let connection =
        wmi::WMIConnection::with_namespace_path("ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption")
            .map_err(|error| PlatformError::Other(error.to_string()))?;
    let volumes: Vec<Win32_EncryptableVolume> = connection
        .raw_query("SELECT __Path,DriveLetter,ProtectionStatus FROM Win32_EncryptableVolume")
        .map_err(|error| PlatformError::Other(error.to_string()))?;
    let volume = volumes
        .into_iter()
        .find(|volume| volume.DriveLetter.as_deref() == Some(mount_point))
        .ok_or_else(|| PlatformError::Other("volumen BitLocker no encontrado".into()))?;
    let result: MethodResult = connection
        .exec_instance_method::<Win32_EncryptableVolume, MethodResult>(
            &volume.__Path,
            "EnableKeyProtectors",
            (),
        )
        .map_err(|error| PlatformError::Other(error.to_string()))?;
    if result.return_value != 0 {
        return Err(PlatformError::Other(format!(
            "EnableKeyProtectors devolvió {}",
            result.return_value
        )));
    }
    Ok(())
}

pub fn inventory() -> Inventory {
    let mut result = Inventory {
        uptime_millis: unsafe { GetTickCount64() },
        ..Inventory::default()
    };
    macro_rules! field {
        ($field:ident,$operation:expr) => {
            match $operation {
                Ok(v) => result.$field = v,
                Err(e) => result.errors.push(format!("{}: {e}", stringify!($field))),
            }
        };
    }
    field!(hostname, hostname().map(Some));
    field!(
        os_version,
        registry("ProductName").and_then(|n| Ok(Some(format!(
            "{n} build {}",
            registry("CurrentBuildNumber")?
        ))))
    );
    field!(adapters, adapters());
    field!(wifi, wifi());
    field!(interactive_users, users());
    let mut memory: MEMORYSTATUSEX = unsafe { zeroed() };
    memory.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    if unsafe { GlobalMemoryStatusEx(&mut memory) } != 0 {
        result.ram_usable_bytes = Some(memory.ullTotalPhys);
    } else {
        result.errors.push(format!("RAM: {}", error()));
    }
    let mut installed = 0u64;
    if unsafe { GetPhysicallyInstalledSystemMemory(&mut installed) } != 0 {
        result.ram_installed_bytes = installed.checked_mul(1024);
    }
    let root = std::env::var_os("SystemDrive").unwrap_or_else(|| "C:".into());
    let root = wide(format!("{}\\", root.to_string_lossy()));
    let mut available = 0;
    let mut total = 0;
    let mut free = 0;
    if unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut available, &mut total, &mut free) } != 0 {
        result.disk_total_bytes = Some(total);
        result.disk_free_bytes = Some(free);
    }
    match wmi::WMIConnection::new()
        .and_then(|c| c.raw_query::<Bios>("SELECT SerialNumber FROM Win32_BIOS"))
    {
        Ok(v) => result.bios_serial = v.first().and_then(|v| v.serial_number.clone()),
        Err(e) => result.errors.push(format!("BIOS: {e}")),
    }
    fn query(namespace: &str, sql: &str, key: &str) -> std::result::Result<String, wmi::WMIError> {
        let c = wmi::WMIConnection::with_namespace_path(namespace)?;
        let v: Vec<HashMap<String, wmi::Variant>> = c.raw_query(sql)?;
        Ok(v.iter()
            .filter_map(|v| v.get(key))
            .map(|v| format!("{v:?}"))
            .collect::<Vec<_>>()
            .join(", "))
    }
    field!(
        defender_status,
        query(
            "ROOT\\Microsoft\\Windows\\Defender",
            "SELECT AMServiceEnabled FROM MSFT_MpComputerStatus",
            "AMServiceEnabled"
        )
        .map(Some)
        .map_err(|e| PlatformError::Other(e.to_string()))
    );
    match bitlocker_volumes() {
        Ok(volumes) => {
            let protected = volumes
                .iter()
                .filter(|volume| volume.protection_status == "on")
                .count();
            let unprotected = volumes
                .iter()
                .filter(|volume| volume.protection_status == "off")
                .count();
            result.bitlocker_status = Some(format!(
                "{protected} protected, {unprotected} unprotected, {} total",
                volumes.len()
            ));
            result.bitlocker_volumes = volumes;
        }
        Err(error) => result.errors.push(format!("BitLocker: {error}")),
    }
    result
}
pub fn lock_desktop() -> Result<()> {
    if unsafe { LockWorkStation() } == 0 {
        return Err(error());
    }
    Ok(())
}
pub fn lock_interactive() -> Result<()> {
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        return Err(PlatformError::Other("no hay sesión interactiva".into()));
    }
    let mut token: HANDLE = null_mut();
    if unsafe { WTSQueryUserToken(session, &mut token) } == 0 {
        return Err(error());
    }
    let token = Handle(token);
    let exe = std::env::current_exe()?;
    let app = wide(&exe);
    let mut command = wide(format!("\"{}\" lock-desktop", exe.display()));
    let mut environment: *mut c_void = null_mut();
    if unsafe { CreateEnvironmentBlock(&mut environment, token.0, 0) } == 0 {
        return Err(error());
    }
    let desktop = wide("winsta0\\default");
    let mut startup: STARTUPINFOW = unsafe { zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    startup.lpDesktop = desktop.as_ptr() as *mut u16;
    let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: only the protected current executable, fixed command and active user's
    // token are supplied. No command text or path from the network is used.
    let ok = unsafe {
        CreateProcessAsUserW(
            token.0,
            app.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_UNICODE_ENVIRONMENT,
            environment,
            null(),
            &startup,
            &mut process,
        )
    };
    unsafe {
        DestroyEnvironmentBlock(environment);
    }
    if ok == 0 {
        return Err(error());
    }
    let process_handle = Handle(process.hProcess);
    let _thread = Handle(process.hThread);
    if unsafe { WaitForSingleObject(process_handle.0, 10000) } != WAIT_OBJECT_0 {
        return Err(PlatformError::Other(
            "helper de bloqueo sin confirmación".into(),
        ));
    }
    let mut exit = 0;
    if unsafe { GetExitCodeProcess(process_handle.0, &mut exit) } == 0 || exit != 0 {
        return Err(PlatformError::Other("falló bloqueo interactivo".into()));
    }
    Ok(())
}
fn service(name: &str, start: bool) -> Result<()> {
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| PlatformError::Other(e.to_string()))?;
    let service = manager
        .open_service(
            name,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
        )
        .map_err(|e| PlatformError::Other(e.to_string()))?;
    let target = if start {
        ServiceState::Running
    } else {
        ServiceState::Stopped
    };
    if service
        .query_status()
        .map_err(|e| PlatformError::Other(e.to_string()))?
        .current_state
        == target
    {
        return Ok(());
    }
    if start {
        service
            .start::<&str>(&[])
            .map_err(|e| PlatformError::Other(e.to_string()))?;
    } else {
        service
            .stop()
            .map_err(|e| PlatformError::Other(e.to_string()))?;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if service
            .query_status()
            .map_err(|e| PlatformError::Other(e.to_string()))?
            .current_state
            == target
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(PlatformError::Other(
        "servicio no alcanzó estado esperado".into(),
    ))
}
pub fn restart_service(name: &str) -> Result<()> {
    service(name, false)?;
    service(name, true)
}
pub fn stop_agent_service() -> Result<()> {
    service("PuniShellAgent", false)
}
pub fn start_agent_service() -> Result<()> {
    service("PuniShellAgent", true)
}
pub fn verify_authenticode(path: &Path, certificate: &str) -> Result<()> {
    let path = wide(path);
    let mut file: WINTRUST_FILE_INFO = unsafe { zeroed() };
    file.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
    file.pcwszFilePath = path.as_ptr();
    let mut trust: WINTRUST_DATA = unsafe { zeroed() };
    trust.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.Anonymous.pFile = &mut file;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &mut action,
            (&mut trust as *mut WINTRUST_DATA).cast(),
        )
    };
    let mut matched = false;
    if status == 0 {
        let data = unsafe { WTHelperProvDataFromStateData(trust.hWVTStateData) };
        if !data.is_null() {
            let signer = unsafe { WTHelperGetProvSignerFromChain(data, 0, 0, 0) };
            if !signer.is_null() && unsafe { (*signer).csCertChain } > 0 {
                let cert = unsafe { (*(*signer).pasCertChain).pCert };
                if !cert.is_null() {
                    let bytes = unsafe {
                        std::slice::from_raw_parts(
                            (*cert).pbCertEncoded,
                            (*cert).cbCertEncoded as usize,
                        )
                    };
                    matched =
                        format!("{:x}", Sha256::digest(bytes)).eq_ignore_ascii_case(certificate);
                }
            }
        }
    }
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            null_mut(),
            &mut action,
            (&mut trust as *mut WINTRUST_DATA).cast(),
        );
    }
    if status != 0 || !matched {
        return Err(PlatformError::Other(
            "Authenticode/certificado de editor no válido".into(),
        ));
    }
    Ok(())
}
