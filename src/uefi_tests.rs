extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::prelude::Status;
use uefi::runtime::{self, ResetType};

use crate::args::{parse_load_options, parse_ucs2_args};
use crate::env::parser::{parse_loader_conf_text, parse_loader_env_text};
use crate::kernel::elf::ElfLoader;
use crate::kernel::module::Module;
use crate::kernel::modulep::ModulepBuilder;
use crate::kernel::types::{MODINFO_ADDR, MODINFO_NAME, MODINFO_SIZE, MODINFO_TYPE, ModuleType};
use crate::uefi_helpers::partition_guid_from_device_path_bytes;

pub fn run() -> Status {
    let mut failures = 0u32;
    if let Err(msg) = test_parse_args() {
        log::error!("test_parse_args: {}", msg);
        failures += 1;
    }
    if let Err(msg) = test_parse_loader_env() {
        log::error!("test_parse_loader_env: {}", msg);
        failures += 1;
    }
    if let Err(msg) = test_parse_loader_conf() {
        log::error!("test_parse_loader_conf: {}", msg);
        failures += 1;
    }
    if let Err(msg) = test_gpt_parsers() {
        log::error!("test_gpt_parsers: {}", msg);
        failures += 1;
    }
    if let Err(msg) = test_ufs_parser() {
        log::error!("test_ufs_parser: {}", msg);
        failures += 1;
    }
    if let Err(msg) = test_device_path_guid() {
        log::error!("test_device_path_guid: {}", msg);
        failures += 1;
    }
    if let Err(msg) = test_modulep_builder() {
        log::error!("test_modulep_builder: {}", msg);
        failures += 1;
    }
    if let Err(msg) = test_elf_loader() {
        log::error!("test_elf_loader: {}", msg);
        failures += 1;
    }

    if failures == 0 {
        log::info!("UEFI tests: all passed");
        qemu_exit(0x10);
    } else {
        log::warn!("UEFI tests: {} failed", failures);
        qemu_exit(0x11);
    }
}

fn test_parse_args() -> Result<(), String> {
    let raw = [
        b'l' as u16,
        b'o' as u16,
        b'a' as u16,
        b'd' as u16,
        b'e' as u16,
        b'r' as u16,
        b'.' as u16,
        b'e' as u16,
        b'f' as u16,
        b'i' as u16,
        b' ' as u16,
        b'-' as u16,
        b'v' as u16,
        0,
    ];
    let args = parse_ucs2_args(&raw);
    if args != alloc::vec!["loader.efi".to_string(), "-v".to_string()] {
        return Err("unexpected args split".into());
    }
    let args = parse_load_options(None, true);
    if args != alloc::vec!["loader.efi".to_string()] {
        return Err("missing loader.efi default".into());
    }
    Ok(())
}

fn test_parse_loader_env() -> Result<(), String> {
    let vars = parse_loader_env_text("foo=1 bar=two");
    if vars.len() != 2 {
        return Err("loader.env parse count mismatch".into());
    }
    if vars[0].key != "foo" || vars[0].value != "1" {
        return Err("loader.env first pair mismatch".into());
    }
    Ok(())
}

fn test_parse_loader_conf() -> Result<(), String> {
    let input = r#"
        # comment
        kern.geom.label.disk_ident.enable="0"
        boot_verbose="YES"
    "#;
    let vars = parse_loader_conf_text(input);
    if vars.len() != 2 {
        return Err("loader.conf parse count mismatch".into());
    }
    Ok(())
}

fn test_gpt_parsers() -> Result<(), String> {
    let mut buf = alloc::vec![0u8; 512];
    buf[0..8].copy_from_slice(b"EFI PART");
    buf[12..16].copy_from_slice(&92u32.to_le_bytes());
    buf[72..80].copy_from_slice(&2u64.to_le_bytes());
    buf[80..84].copy_from_slice(&128u32.to_le_bytes());
    buf[84..88].copy_from_slice(&128u32.to_le_bytes());
    if !crate::gpt::test_parse_header_ok(&buf) {
        return Err("gpt header parse failed".into());
    }

    let mut part = alloc::vec![0u8; crate::gpt::GPT_ENTRY_MIN_SIZE];
    part[0] = 0xAA;
    part[16] = 0xBB;
    if !crate::gpt::test_parse_partition_ok(1, &part) {
        return Err("gpt partition parse failed".into());
    }
    Ok(())
}

fn test_ufs_parser() -> Result<(), String> {
    let mut buf = alloc::vec![0u8; crate::fs::ufs::SBLOCKSIZE];
    buf[crate::fs::ufs::FS_MAGIC_OFFSET..crate::fs::ufs::FS_MAGIC_OFFSET + 4]
        .copy_from_slice(&crate::fs::ufs::FS_UFS2_MAGIC.to_le_bytes());
    let offset = crate::fs::ufs::FS_SBLOCKLOC_OFFSET;
    buf[offset..offset + 8].copy_from_slice(&crate::fs::ufs::SBLOCK_OFFSETS[0].to_le_bytes());
    let kind = crate::fs::ufs::test_parse_superblock(&buf, crate::fs::ufs::SBLOCK_OFFSETS[0]);
    if kind != Some(crate::fs::ufs::UfsKind::Ufs2) {
        return Err("ufs superblock parse failed".into());
    }
    Ok(())
}

fn test_device_path_guid() -> Result<(), String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x04, 0x01, 0x2A, 0x00]);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    let mut guid = [0u8; 16];
    guid[0] = 0x11;
    bytes.extend_from_slice(&guid);
    bytes.push(0x02);
    bytes.push(0x02);
    bytes.extend_from_slice(&[0x7f, 0xff, 0x04, 0x00]);
    let parsed = partition_guid_from_device_path_bytes(&bytes).ok_or("guid parse failed")?;
    if parsed[0] != 0x11 {
        return Err("guid mismatch".into());
    }
    Ok(())
}

fn test_modulep_builder() -> Result<(), String> {
    let mut builder = ModulepBuilder::new();
    builder.add_name("kernel");
    builder.add_type(ModuleType::ElfKernel);
    builder.add_addr(0x1000);
    builder.add_size(0x2000);

    let mut module = Module::new(String::from("if_foo.ko"), ModuleType::ElfModule, Vec::new());
    module.set_physical_address(0x3000);
    if !builder.add_module(&module) {
        return Err("module add failed".into());
    }
    let buf = builder.finish();
    let tags: Vec<u32> = buf
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();
    if !tags.iter().any(|&tag| tag == MODINFO_NAME) {
        return Err("modulep missing name".into());
    }
    if !tags.iter().any(|&tag| tag == MODINFO_TYPE) {
        return Err("modulep missing type".into());
    }
    if !tags.iter().any(|&tag| tag == MODINFO_ADDR) {
        return Err("modulep missing addr".into());
    }
    if !tags.iter().any(|&tag| tag == MODINFO_SIZE) {
        return Err("modulep missing size".into());
    }
    Ok(())
}

fn test_elf_loader() -> Result<(), String> {
    let mut image = alloc::vec![0u8; 64 + 56];
    image[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    image[16..18].copy_from_slice(&2u16.to_le_bytes());
    image[18..20].copy_from_slice(&62u16.to_le_bytes());
    image[24..32].copy_from_slice(&0x100000u64.to_le_bytes());
    image[32..40].copy_from_slice(&(64u64).to_le_bytes());
    image[54..56].copy_from_slice(&(56u16).to_le_bytes());
    image[56..58].copy_from_slice(&(1u16).to_le_bytes());

    let phdr = 64;
    image[phdr..phdr + 4].copy_from_slice(&1u32.to_le_bytes());
    image[phdr + 4..phdr + 8].copy_from_slice(&5u32.to_le_bytes());
    image[phdr + 8..phdr + 16].copy_from_slice(&0x1000u64.to_le_bytes());
    image[phdr + 16..phdr + 24].copy_from_slice(&0x100000u64.to_le_bytes());
    image[phdr + 24..phdr + 32].copy_from_slice(&0x100000u64.to_le_bytes());
    image[phdr + 32..phdr + 40].copy_from_slice(&0x2000u64.to_le_bytes());
    image[phdr + 40..phdr + 48].copy_from_slice(&0x3000u64.to_le_bytes());
    image[phdr + 48..phdr + 56].copy_from_slice(&0x200000u64.to_le_bytes());

    let loader = ElfLoader;
    let info = loader
        .parse_kernel(&image)
        .map_err(|_| "elf parse failed")?;
    if info.program_headers.is_empty() {
        return Err("elf phdrs missing".into());
    }
    Ok(())
}

fn qemu_exit(code: u32) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xf4u16, in("eax") code);
    }
    runtime::reset(
        ResetType::SHUTDOWN,
        if code == 0x10 {
            Status::SUCCESS
        } else {
            Status::ABORTED
        },
        None,
    );
}
