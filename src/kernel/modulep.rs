extern crate alloc;

use alloc::vec::Vec;

use crate::kernel::types::{
    MODINFO_ADDR, MODINFO_ARGS, MODINFO_END, MODINFO_METADATA, MODINFO_NAME, MODINFO_SIZE,
    MODINFO_TYPE, ModInfoMd,
};
use alloc::string::ToString;

use crate::kernel::{module::Module, types::ModuleType};

pub struct ModulepBuilder {
    buf: Vec<u8>,
}

impl ModulepBuilder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn add_name(&mut self, name: &str) {
        self.add_string(MODINFO_NAME, name);
    }

    pub fn add_type(&mut self, module_type: ModuleType) {
        self.add_string(MODINFO_TYPE, &module_type.to_string());
    }

    pub fn add_addr(&mut self, addr: u64) {
        self.add_u64(MODINFO_ADDR, addr);
    }

    pub fn add_size(&mut self, size: u64) {
        self.add_u64(MODINFO_SIZE, size);
    }

    pub fn add_args(&mut self, args: &str) {
        if !args.is_empty() {
            self.add_string(MODINFO_ARGS, args);
        }
    }

    pub fn add_u64(&mut self, type_: u32, value: u64) {
        self.push_u32(type_);
        self.push_u32(8);
        self.buf.extend_from_slice(&value.to_le_bytes());
        self.align_ptr();
    }

    #[allow(dead_code)]
    pub fn add_u32(&mut self, type_: u32, value: u32) {
        self.push_u32(type_);
        self.push_u32(4);
        self.buf.extend_from_slice(&value.to_le_bytes());
        self.align_ptr();
    }

    pub fn add_bytes(&mut self, type_: u32, bytes: &[u8]) {
        self.push_u32(type_);
        self.push_u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
        self.align_ptr();
    }

    pub fn add_string(&mut self, type_: u32, value: &str) {
        self.push_u32(type_);
        self.push_u32((value.len() + 1) as u32);
        self.buf.extend_from_slice(value.as_bytes());
        self.buf.push(0);
        self.align_ptr();
    }

    pub fn add_metadata_bytes(&mut self, md: ModInfoMd, bytes: &[u8]) {
        self.add_bytes(MODINFO_METADATA | md as u32, bytes);
    }

    pub fn add_metadata_u64(&mut self, md: ModInfoMd, value: u64) {
        self.add_u64(MODINFO_METADATA | md as u32, value);
    }

    pub fn add_metadata_u32(&mut self, md: ModInfoMd, value: u32) {
        self.add_u32(MODINFO_METADATA | md as u32, value);
    }

    pub fn add_end(&mut self) {
        self.push_u32(MODINFO_END);
        self.push_u32(0);
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.add_end();
        self.buf
    }

    pub fn add_module(&mut self, module: &Module) -> bool {
        self.add_name(&module.name);
        self.add_type(module.module_type.clone());
        if let Some(args) = module.args.as_deref() {
            self.add_args(args);
        }
        if let Some(addr) = module.phys_addr {
            self.add_addr(addr);
            self.add_size(module.data_len as u64);
            if let Some(header) = module.elf_header.as_ref() {
                self.add_metadata_bytes(ModInfoMd::Elfhdr, header);
            }
            if !module.section_headers.is_empty() {
                if let Some(shdr) = relocated_section_headers(
                    &module.section_headers,
                    &module.section_addr_offsets,
                    addr,
                ) {
                    self.add_metadata_bytes(ModInfoMd::Shdr, &shdr);
                }
            }
            true
        } else {
            false
        }
    }

    fn push_u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn align_ptr(&mut self) {
        let align = core::mem::size_of::<u64>();
        let pad = (align - (self.buf.len() % align)) % align;
        self.buf.extend_from_slice(&alloc::vec![0u8; pad]);
    }
}

fn relocated_section_headers(
    section_headers: &[u8],
    section_addr_offsets: &[Option<u64>],
    base: u64,
) -> Option<Vec<u8>> {
    let shentsize = 64usize;
    if section_headers.len() % shentsize != 0
        || section_addr_offsets.len() != section_headers.len() / shentsize
    {
        return None;
    }
    let mut out = section_headers.to_vec();
    for (index, chunk) in out.chunks_mut(shentsize).enumerate() {
        if let Some(rel_addr) = section_addr_offsets[index] {
            let addr = base.checked_add(rel_addr)?;
            chunk[16..24].copy_from_slice(&addr.to_le_bytes());
        } else {
            chunk[16..24].copy_from_slice(&0u64.to_le_bytes());
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::ModulepBuilder;
    use crate::kernel::module::Module;
    use crate::kernel::types::{
        MODINFO_ADDR, MODINFO_END, MODINFO_METADATA, MODINFO_NAME, MODINFO_SIZE, MODINFO_TYPE,
        ModInfoMd, ModuleType,
    };

    #[test]
    fn test_modulep_builder_adds_end() {
        let mut builder = ModulepBuilder::new();
        builder.add_name("kernel");
        let buf = builder.finish();

        let end_tag = u32::from_le_bytes([
            buf[buf.len() - 8],
            buf[buf.len() - 7],
            buf[buf.len() - 6],
            buf[buf.len() - 5],
        ]);
        assert_eq!(end_tag, MODINFO_END);
    }

    #[test]
    fn test_modulep_builder_adds_name() {
        let mut builder = ModulepBuilder::new();
        builder.add_name("kernel");
        let buf = builder.finish();

        let tag = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(tag, MODINFO_NAME);
    }

    #[test]
    fn test_modulep_builder_module_ordering() {
        let mut builder = ModulepBuilder::new();
        builder.add_name("kernel");
        builder.add_type(ModuleType::ElfKernel);
        builder.add_addr(0x1000);
        builder.add_size(0x2000);

        let mut module = Module::new(String::from("if_foo.ko"), ModuleType::ElfModule, Vec::new());
        module.set_physical_address(0x3000);
        assert!(builder.add_module(&module));

        let buf = builder.finish();
        let tags = decode_tags(&buf);

        let first = find_tag_sequence(
            &tags,
            &[MODINFO_NAME, MODINFO_TYPE, MODINFO_ADDR, MODINFO_SIZE],
        )
        .expect("first module sequence");
        let second = find_tag_sequence(
            &tags[first + 1..],
            &[MODINFO_NAME, MODINFO_TYPE, MODINFO_ADDR, MODINFO_SIZE],
        )
        .expect("second module sequence");
        assert!(first + 1 + second > first);
    }

    #[test]
    fn test_modulep_builder_adds_elf_obj_metadata() {
        let mut module = Module::new(String::from("zfs.ko"), ModuleType::ElfObj, Vec::new());
        module.set_physical_address(0x1000);
        module.set_data_len(0x4000);
        let header = [0x7fu8; 64];
        let shdr = vec![0u8; 64];
        module.set_elf_metadata(header, shdr, vec![Some(0x200)]);

        let mut builder = ModulepBuilder::new();
        assert!(builder.add_module(&module));
        let buf = builder.finish();
        let records = decode_records(&buf);

        assert!(records.iter().any(|(tag, size, _)| *tag
            == (MODINFO_METADATA | ModInfoMd::Elfhdr as u32)
            && *size == 64));
        let (_, _, shdr_offset) = records
            .iter()
            .find(|(tag, size, _)| {
                *tag == (MODINFO_METADATA | ModInfoMd::Shdr as u32) && *size == 64
            })
            .expect("section header metadata");
        let relocated = u64::from_le_bytes(
            buf[*shdr_offset + 16..*shdr_offset + 24]
                .try_into()
                .expect("u64 section address"),
        );
        assert_eq!(relocated, 0x1200);
    }

    fn decode_tags(buf: &[u8]) -> Vec<u32> {
        decode_records(buf)
            .into_iter()
            .map(|(tag, _, _)| tag)
            .collect()
    }

    fn decode_records(buf: &[u8]) -> Vec<(u32, usize, usize)> {
        let mut tags = Vec::new();
        let mut offset = 0usize;
        while offset + 8 <= buf.len() {
            let tag = u32::from_le_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]);
            let size = u32::from_le_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ]) as usize;
            tags.push((tag, size, offset + 8));
            let mut next = offset + 8 + size;
            let rem = next % 8;
            if rem != 0 {
                next += 8 - rem;
            }
            if next <= offset {
                break;
            }
            offset = next;
            if tag == MODINFO_END {
                break;
            }
        }
        tags
    }

    fn find_tag_sequence(tags: &[u32], seq: &[u32]) -> Option<usize> {
        if seq.is_empty() {
            return None;
        }
        for idx in 0..tags.len().saturating_sub(seq.len() - 1) {
            if tags[idx..idx + seq.len()] == *seq {
                return Some(idx);
            }
        }
        None
    }
}
