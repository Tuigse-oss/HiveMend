//! Live Service Control Manager backend. Listing is read-only; writes go
//! through the same refusal and backup rules as every other store because
//! the apply layer enforces them.

use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, GetLastError,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
    QUERY_SERVICE_CONFIGW, QueryServiceConfig2W, QueryServiceConfigW, QueryServiceStatusEx,
    SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE,
    SC_STATUS_PROCESS_INFO, SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
    SERVICE_CONTROL_STOP, SERVICE_DELAYED_AUTO_START_INFO, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATE_ALL, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
    SERVICE_STOP, SERVICE_WIN32, StartServiceW,
};

use crate::services::{ServiceInfo, ServiceState, ServiceStore, StartType, StoreError, Transition};

#[derive(Clone, Copy, Debug, Default)]
pub struct ScmServiceStore;

struct ScHandle {
    handle: SC_HANDLE,
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                CloseServiceHandle(self.handle);
            }
        }
    }
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

/// Scratch space for variable-length SCM out-params. The structs read back
/// out of it contain pointers (8-byte alignment on x64), so a plain Vec<u8>
/// (guaranteed alignment 1) cannot back them. A Vec<u64> can.
fn aligned_buffer(bytes: usize) -> Vec<u64> {
    vec![0u64; bytes.div_ceil(8)]
}

/// Common service error codes in plain words. Only access-denied counts as
/// a rights problem; the rest are state the caller reports.
fn scm_error(code: u32, what: &str) -> StoreError {
    match code {
        ERROR_ACCESS_DENIED => StoreError::denied(format!(
            "{what}: Windows refused; run as administrator and try again"
        )),
        1060 => StoreError::new(format!("{what}: no such service")),
        1058 => StoreError::new(format!("{what}: cannot start a disabled service")),
        1051 => StoreError::new(format!("{what}: it has running services that depend on it")),
        1072 => StoreError::new(format!("{what}: it is marked for deletion")),
        _ => StoreError::new(format!("{what}: service call failed ({code})")),
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn read_pwstr(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut len = 0;
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) })
}

fn open_manager(access: u32) -> Result<ScHandle, StoreError> {
    let handle = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), access) };
    if handle.is_null() {
        return Err(scm_error(last_error(), "opening the service database"));
    }
    Ok(ScHandle { handle })
}

fn open_service(manager: &ScHandle, name: &str, access: u32) -> Result<ScHandle, StoreError> {
    let wide = wide(name);
    let handle = unsafe { OpenServiceW(manager.handle, wide.as_ptr(), access) };
    if handle.is_null() {
        return Err(scm_error(last_error(), name));
    }
    Ok(ScHandle { handle })
}

/// Whole-listing enumeration. The service set can change between the size
/// probe and the fetch, so a short-changed fetch restarts from scratch with
/// a fresh probe instead of resuming: every attempt either returns a
/// complete list or retries, and the attempts are bounded.
fn enumerate(manager: &ScHandle) -> Result<Vec<ServiceInfo>, StoreError> {
    for _ in 0..5 {
        let mut resume = 0u32;
        let mut needed = 0u32;
        let mut returned = 0u32;
        let ok = unsafe {
            EnumServicesStatusExW(
                manager.handle,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                ptr::null_mut(),
                0,
                &mut needed,
                &mut returned,
                &mut resume,
                ptr::null(),
            )
        };
        if ok != 0 {
            return Ok(Vec::new());
        }
        let code = last_error();
        if code != ERROR_MORE_DATA || needed == 0 {
            return Err(scm_error(code, "listing services"));
        }
        let mut buffer = aligned_buffer(needed as usize);
        let bytes = (buffer.len() * 8) as u32;
        let ok = unsafe {
            EnumServicesStatusExW(
                manager.handle,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr() as *mut u8,
                bytes,
                &mut needed,
                &mut returned,
                &mut resume,
                ptr::null(),
            )
        };
        if ok == 0 {
            if last_error() == ERROR_MORE_DATA {
                continue;
            }
            return Err(scm_error(last_error(), "listing services"));
        }
        if resume != 0 {
            continue;
        }
        let mut services = Vec::new();
        let entries = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                returned as usize,
            )
        };
        for entry in entries {
            let name = read_pwstr(entry.lpServiceName);
            if name.is_empty() {
                continue;
            }
            // Services whose configuration cannot be read (gone
            // mid-listing, locked down) are skipped; the list never fails
            // for one row.
            let Some(start) = query_start(manager, &name) else {
                continue;
            };
            services.push(ServiceInfo {
                display_name: read_pwstr(entry.lpDisplayName),
                state: ServiceState::from_dword(entry.ServiceStatusProcess.dwCurrentState),
                name,
                start,
            });
        }
        return Ok(services);
    }
    Err(scm_error(ERROR_MORE_DATA, "listing services"))
}

/// The Start value a start type is written as, for the types Hivemend sets.
fn start_dword(to: StartType) -> Option<u32> {
    match to {
        StartType::Automatic | StartType::AutomaticDelayed => Some(2),
        StartType::Manual => Some(3),
        StartType::Disabled => Some(4),
        StartType::Boot | StartType::System => None,
    }
}

fn query_start(manager: &ScHandle, name: &str) -> Option<StartType> {
    let service = open_service(manager, name, SERVICE_QUERY_CONFIG).ok()?;
    let mut needed = 0u32;
    unsafe {
        QueryServiceConfigW(service.handle, ptr::null_mut(), 0, &mut needed);
    }
    if last_error() != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
        return None;
    }
    let mut buffer = aligned_buffer(needed as usize);
    let bytes = (buffer.len() * 8) as u32;
    let ok = unsafe {
        QueryServiceConfigW(
            service.handle,
            buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
            bytes,
            &mut needed,
        )
    };
    if ok == 0 {
        return None;
    }
    let config = unsafe { &*(buffer.as_ptr() as *const QUERY_SERVICE_CONFIGW) };
    let mut delayed_info: SERVICE_DELAYED_AUTO_START_INFO = unsafe { std::mem::zeroed() };
    let mut delayed_needed = 0u32;
    let delayed = unsafe {
        QueryServiceConfig2W(
            service.handle,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            &mut delayed_info as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_DELAYED_AUTO_START_INFO>() as u32,
            &mut delayed_needed,
        ) != 0
            && delayed_info.fDelayedAutostart != 0
    };
    StartType::from_dword(config.dwStartType, delayed)
}

fn query_state(service: &ScHandle) -> Option<u32> {
    let mut buffer = aligned_buffer(std::mem::size_of::<SERVICE_STATUS_PROCESS>());
    let mut needed = 0u32;
    let ok = unsafe {
        QueryServiceStatusEx(
            service.handle,
            SC_STATUS_PROCESS_INFO,
            buffer.as_mut_ptr() as *mut u8,
            (buffer.len() * 8) as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return None;
    }
    Some(unsafe { (*(buffer.as_ptr() as *const SERVICE_STATUS_PROCESS)).dwCurrentState })
}

/// Wait up to about ten seconds for a service to settle, and return where it
/// ended. Starting and stopping are asynchronous, so a request the service
/// control manager accepted is not yet a done change: the caller counts only
/// `Reached`. A wait that ends pending, back where it began, or with an
/// unreadable status reports that last state instead.
fn wait_for_state(manager: &ScHandle, name: &str, running: bool) -> Transition {
    let want = if running {
        ServiceState::Running
    } else {
        ServiceState::Stopped
    };
    let mut last = ServiceState::Other;
    for attempt in 0..20 {
        last = open_service(manager, name, SERVICE_QUERY_STATUS)
            .ok()
            .and_then(|service| query_state(&service))
            .map(ServiceState::from_dword)
            .unwrap_or(ServiceState::Other);
        if last == want {
            return Transition::Reached;
        }
        if attempt + 1 < 20 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    Transition::NotReached(last)
}

impl ServiceStore for ScmServiceStore {
    fn list(&self) -> Result<Vec<ServiceInfo>, crate::model::Error> {
        let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)?;
        enumerate(&manager).map_err(|err| err.into())
    }

    fn set_start(&mut self, name: &str, to: StartType) -> Result<(), StoreError> {
        // Defense in depth: the apply layer refuses these first.
        let (start, delayed) = match to {
            StartType::Automatic => (2u32, Some(0)),
            StartType::AutomaticDelayed => (2u32, Some(1)),
            StartType::Manual => (3u32, None),
            StartType::Disabled => (4u32, None),
            StartType::Boot | StartType::System => {
                return Err(StoreError::new(format!(
                    "{name}: refusing a Boot or System start"
                )));
            }
        };
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        // Read first, so a failed second step can be undone.
        let service = open_service(&manager, name, SERVICE_CHANGE_CONFIG)?;
        // The state to go back to must be known before anything changes;
        // without it a failed second step could not be undone.
        let Some(prior) = query_start(&manager, name) else {
            return Err(StoreError::new(format!(
                "{name}: its current start type could not be read, so it was left as it is"
            )));
        };
        let ok = unsafe {
            ChangeServiceConfigW(
                service.handle,
                SERVICE_NO_CHANGE,
                start,
                SERVICE_NO_CHANGE,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(scm_error(last_error(), name));
        }
        // A stale delay flag is meaningless unless Start is Automatic, so
        // only Automatic targets rewrite it; Manual and Disabled leave it
        // exactly as `sc.exe` would.
        if let Some(delayed) = delayed {
            let info = SERVICE_DELAYED_AUTO_START_INFO {
                fDelayedAutostart: delayed,
            };
            let ok = unsafe {
                ChangeServiceConfig2W(
                    service.handle,
                    SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                    &info as *const _ as *const _,
                )
            };
            if ok == 0 {
                let failed = scm_error(last_error(), name);
                // Start already changed: put it back, so a failed request
                // never leaves a different mode behind.
                let restored = start_dword(prior).is_some_and(|dword| unsafe {
                    ChangeServiceConfigW(
                        service.handle,
                        SERVICE_NO_CHANGE,
                        dword,
                        SERVICE_NO_CHANGE,
                        ptr::null(),
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                    ) != 0
                });
                return Err(StoreError {
                    message: format!(
                        "{}; {}",
                        failed.message,
                        if restored {
                            "the start type was put back as it was"
                        } else {
                            "the start type could not be put back, so restore this change's backup"
                        }
                    ),
                    denied: failed.denied,
                });
            }
        }
        Ok(())
    }

    fn start(&mut self, name: &str) -> Result<Transition, StoreError> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_service(&manager, name, SERVICE_START | SERVICE_QUERY_STATUS)?;
        let ok = unsafe { StartServiceW(service.handle, 0, ptr::null()) };
        if ok == 0 {
            let code = last_error();
            if code == 1056 {
                return Ok(Transition::AlreadyThere);
            }
            return Err(scm_error(code, name));
        }
        Ok(wait_for_state(&manager, name, true))
    }

    fn stop(&mut self, name: &str) -> Result<Transition, StoreError> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_service(&manager, name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        let ok = unsafe { ControlService(service.handle, SERVICE_CONTROL_STOP, &mut status) };
        if ok == 0 {
            let code = last_error();
            if code == 1062 {
                return Ok(Transition::AlreadyThere);
            }
            return Err(scm_error(code, name));
        }
        Ok(wait_for_state(&manager, name, false))
    }
}

/// Live Windows tests. Read-only, plus one write call against a service
/// name that cannot exist (it must fail before touching anything).
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;

    #[test]
    fn live_list_finds_core_services() {
        let store = ScmServiceStore;
        let services = store.list().expect("list services");
        assert!(!services.is_empty());
        assert!(services.iter().any(|service| service.name == "RpcSs"));
    }

    #[test]
    fn live_set_start_on_missing_service_errors() {
        let mut store = ScmServiceStore;
        let err = store
            .set_start("HiveMendNoSuchService", StartType::Manual)
            .unwrap_err();
        assert!(
            err.message.contains("no such service"),
            "unexpected: {err:?}"
        );
    }
}
