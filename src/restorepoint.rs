//! A Windows System Restore point around a repair: a second safety net on
//! top of Hivemend's own `.reg` backup. Creating one needs administrator
//! rights and System Protection turned on for the system drive, and Windows
//! itself makes at most one per day by default, so a failure here never
//! stops a repair; it is only reported.

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SERVICE_DISABLED};
use windows_sys::Win32::System::Restore::{
    BEGIN_SYSTEM_CHANGE, CANCELLED_OPERATION, END_SYSTEM_CHANGE, MODIFY_SETTINGS,
    RESTOREPOINTINFOW, SRSetRestorePointW, STATEMGRSTATUS,
};

/// A restore point that has been opened and must be closed with [`end`].
#[derive(Debug)]
pub struct RestorePoint {
    sequence: i64,
}

fn info(event: u32, kind: u32, sequence: i64, description: &str) -> RESTOREPOINTINFOW {
    let mut text = [0u16; 256];
    for (slot, unit) in text.iter_mut().zip(description.encode_utf16().take(255)) {
        *slot = unit;
    }
    RESTOREPOINTINFOW {
        dwEventType: event,
        dwRestorePtType: kind,
        llSequenceNumber: sequence,
        szDescription: text,
    }
}

/// Ask Windows to start a restore point named `description`.
pub fn begin(description: &str) -> Result<RestorePoint, String> {
    let spec = info(BEGIN_SYSTEM_CHANGE, MODIFY_SETTINGS, 0, description);
    let mut status = STATEMGRSTATUS::default();
    let ok = unsafe { SRSetRestorePointW(&spec, &mut status) } != 0;
    let code = status.nStatus;
    if !ok || code != 0 {
        return Err(match code {
            ERROR_SERVICE_DISABLED => {
                "System Protection is turned off for the system drive".to_string()
            }
            ERROR_ACCESS_DENIED => "Windows requires administrator rights".to_string(),
            code => format!(
                "Windows refused ({})",
                std::io::Error::from_raw_os_error(code as i32)
            ),
        });
    }
    Ok(RestorePoint {
        sequence: status.llSequenceNumber,
    })
}

/// Close the restore point: keep it after a repair that ran, or cancel it
/// when nothing was changed.
pub fn end(point: RestorePoint, keep: bool) {
    let kind = if keep {
        MODIFY_SETTINGS
    } else {
        CANCELLED_OPERATION
    };
    let spec = info(END_SYSTEM_CHANGE, kind, point.sequence, "");
    let mut status = STATEMGRSTATUS::default();
    unsafe { SRSetRestorePointW(&spec, &mut status) };
}
