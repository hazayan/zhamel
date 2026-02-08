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
    pub args: Option<String>,
    pub data_len: usize,
}

impl Module {
    pub fn new(name: String, module_type: ModuleType, data: Vec<u8>) -> Self {
        let data_len = data.len();
        Self {
            name,
            module_type,
            data,
            phys_addr: None,
            args: None,
            data_len,
        }
    }

    #[allow(dead_code)]
    pub fn with_args(
        name: String,
        module_type: ModuleType,
        data: Vec<u8>,
        args: Option<String>,
    ) -> Self {
        let data_len = data.len();
        Self {
            name,
            module_type,
            data,
            phys_addr: None,
            args,
            data_len,
        }
    }

    pub fn from_phys(
        name: String,
        module_type: ModuleType,
        phys_addr: u64,
        data_len: usize,
        args: Option<String>,
    ) -> Self {
        Self {
            name,
            module_type,
            data: Vec::new(),
            phys_addr: Some(phys_addr),
            args,
            data_len,
        }
    }

    pub fn set_physical_address(&mut self, addr: u64) {
        self.phys_addr = Some(addr);
    }

    pub fn set_args(&mut self, args: Option<String>) {
        self.args = args;
    }

    #[allow(dead_code)]
    pub fn set_data_len(&mut self, len: usize) {
        self.data_len = len;
    }
}
