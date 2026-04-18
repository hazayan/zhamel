extern crate alloc;

use alloc::string::String;
use core::fmt;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleType {
    ElfKernel,
    ElfModule,
    ElfObj,
    Raw(String),
}

impl fmt::Display for ModuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModuleType::ElfKernel => write!(f, "elf kernel"),
            ModuleType::ElfModule => write!(f, "elf module"),
            ModuleType::ElfObj => write!(f, "elf obj module"),
            ModuleType::Raw(name) => write!(f, "{}", name),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum ModInfoMd {
    Ssym = 0x0003,
    Esym = 0x0004,
    Dynamic = 0x0005,
    Envp = 0x0006,
    Howto = 0x0007,
    Kernend = 0x0008,
    Shdr = 0x0009,
    FwHandle = 0x000c,
    KeyBuf = 0x000d,
    Font = 0x000e,
    Elfhdr = 0x0002,
    Smap = 0x1001,
    EfiMap = 0x1004,
    EfiFb = 0x1005,
    Modulep = 0x1006,
    EfiArch = 0x1008,
}

pub const MODINFO_END: u32 = 0x0000;
pub const MODINFO_NAME: u32 = 0x0001;
pub const MODINFO_TYPE: u32 = 0x0002;
pub const MODINFO_ADDR: u32 = 0x0003;
pub const MODINFO_SIZE: u32 = 0x0004;
#[allow(dead_code)]
pub const MODINFO_ARGS: u32 = 0x0006;
pub const MODINFO_METADATA: u32 = 0x8000;

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::string::ToString;

    use super::ModuleType;

    #[test]
    fn test_module_type_display() {
        assert_eq!(ModuleType::ElfKernel.to_string(), "elf kernel");
        assert_eq!(ModuleType::ElfModule.to_string(), "elf module");
        assert_eq!(ModuleType::ElfObj.to_string(), "elf obj module");
        assert_eq!(ModuleType::Raw("custom".to_string()).to_string(), "custom");
    }
}
