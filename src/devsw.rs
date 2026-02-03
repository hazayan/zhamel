extern crate alloc;

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy)]
pub enum DeviceKind {
    Ufs,
    Net,
}

pub fn init() -> Vec<DeviceKind> {
    let devices = alloc::vec![DeviceKind::Ufs, DeviceKind::Net];
    log::info!("devsw: {}", devices.len());
    devices
}
