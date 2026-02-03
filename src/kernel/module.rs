extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::types::ModuleType;

#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub module_type: ModuleType,
    pub data: Vec<u8>,
    pub phys_addr: Option<u64>,
}

impl Module {
    pub fn new(name: String, module_type: ModuleType, data: Vec<u8>) -> Self {
        Self {
            name,
            module_type,
            data,
            phys_addr: None,
        }
    }

    pub fn set_physical_address(&mut self, addr: u64) {
        self.phys_addr = Some(addr);
    }
}
