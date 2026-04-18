use core::ptr;

use uefi::Status;
use uefi::boot;
use uefi::runtime::{self, ResetType};
use uefi::table;

use crate::heap;

#[cfg(all(target_os = "uefi", not(test)))]
pub fn finish(status: Status) -> Status {
    efi_exit(status)
}

#[cfg(any(not(target_os = "uefi"), test))]
pub fn finish(status: Status) -> Status {
    status
}

#[cfg(all(target_os = "uefi", not(test)))]
fn efi_exit(status: Status) -> ! {
    if boot_services_active() {
        heap::free();
        unsafe {
            boot::exit(boot::image_handle(), status, 0, ptr::null_mut());
        }
    }
    runtime::reset(ResetType::COLD, status, None)
}

#[cfg(all(target_os = "uefi", not(test)))]
fn boot_services_active() -> bool {
    table::system_table_raw()
        .map(|st| unsafe { !st.as_ref().boot_services.is_null() })
        .unwrap_or(false)
}
