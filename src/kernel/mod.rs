extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::env::loader::LoaderEnv;
use crate::env::parser::EnvVar;
use crate::fs::uefi::{
    read_dir_entries_from_boot_volume,
    read_dir_entries_from_partition_guid,
    read_file_from_boot_volume,
    read_file_from_partition_guid,
};
use crate::fs::iso9660::{self, IsoVolume};
use uefi::boot::{self, AllocateType, MemoryType, SearchType};
use uefi::proto::media::block::BlockIO;
use uefi::Identify;
use crate::zfs;
use crate::zfs::ZfsPool;
use crate::kernel::module::Module;
use crate::kernel::modulep::ModulepBuilder;
use crate::kernel::types::{ModInfoMd, ModuleType};
use crate::error::{BootError, Result};
use uefi::mem::memory_map::MemoryMap;
use uefi::table;

pub mod elf;
pub mod module;
pub mod modulep;
pub mod types;

const DEFAULT_KERNEL_PATH: &str = "/boot/kernel/kernel";
const DEFAULT_KERNEL_DIR: &str = "/boot/kernel";

pub struct IsoContext {
    handle: uefi::Handle,
    media_id: u32,
    block_size: usize,
    volume: IsoVolume,
}

pub fn read_kernel_from_currdev(guid: [u8; 16], env: &LoaderEnv) -> Option<Vec<u8>> {
    let path = env.get("kernel").unwrap_or(DEFAULT_KERNEL_PATH);
    read_file_from_partition_guid(guid, path)
}

pub fn read_kernel_from_boot_volume(env: &LoaderEnv) -> Option<Vec<u8>> {
    let path = env.get("kernel").unwrap_or(DEFAULT_KERNEL_PATH);
    let bytes = read_file_from_boot_volume(path);
    if bytes.is_none() {
        log::warn!("boot volume kernel read failed: {}", path);
    }
    bytes
}

pub fn read_kernel_from_zfs(
    pools: &[ZfsPool],
    bootenv: &str,
    env: &LoaderEnv,
) -> Option<Vec<u8>> {
    let (pool, dataset) = zfs::find_pool_for_bootenv(pools, bootenv)?;
    let path = env.get("kernel").unwrap_or(DEFAULT_KERNEL_PATH);
    match zfs::fs::read_file_from_bootenv(pool, &dataset, path) {
        Ok(bytes) => Some(bytes),
        Err(err) => {
            log::warn!("zfs kernel read failed: {}", err);
            None
        }
    }
}

pub fn read_kernel_from_zfs_bootfs(
    pools: &[ZfsPool],
    env: &LoaderEnv,
) -> Option<(usize, Vec<u8>)> {
    let path = env.get("kernel").unwrap_or(DEFAULT_KERNEL_PATH);
    for (idx, pool) in pools.iter().enumerate() {
        log::info!("zfs bootfs kernel probe: pool {}", idx);
        let block = match boot::open_protocol_exclusive::<BlockIO>(pool.handle) {
            Ok(block) => block,
            Err(err) => {
                log::warn!("zfs bootfs BlockIO open failed: {:?}", err.status());
                continue;
            }
        };
        let Some(uber) = pool.uber else {
            log::warn!("zfs bootfs kernel read failed: uberblock missing");
            continue;
        };
        let objset = match zfs::fs::bootfs_objset(&block, pool.media_id, pool.block_size, uber) {
            Ok(objset) => objset,
            Err(err) => {
                log::warn!("zfs bootfs kernel read failed: {}", err);
                continue;
            }
        };
        match zfs::fs::read_file_from_objset(&block, pool.media_id, pool.block_size, &objset, path)
        {
            Ok(bytes) => return Some((idx, bytes)),
            Err(err) => {
                log::warn!("zfs bootfs kernel read failed: {}", err);
            }
        }
    }
    None
}

pub fn discover_modules_from_currdev(guid: [u8; 16]) -> Vec<Module> {
    let mut modules = Vec::new();
    let Some(entries) = read_dir_entries_from_partition_guid(guid, DEFAULT_KERNEL_DIR) else {
        return modules;
    };
    for entry in entries {
        if !is_module_filename(&entry) {
            continue;
        }
        let path = format!("{}/{}", DEFAULT_KERNEL_DIR, entry);
        let Some(data) = read_file_from_partition_guid(guid, &path) else {
            continue;
        };
        modules.push(Module::new(
            entry,
            ModuleType::ElfModule,
            data,
        ));
    }
    modules
}

pub fn discover_modules_from_boot_volume() -> Vec<Module> {
    let mut modules = Vec::new();
    let Some(entries) = read_dir_entries_from_boot_volume(DEFAULT_KERNEL_DIR) else {
        return modules;
    };
    for entry in entries {
        if !is_module_filename(&entry) {
            continue;
        }
        let path = format!("{}/{}", DEFAULT_KERNEL_DIR, entry);
        let Some(data) = read_file_from_boot_volume(&path) else {
            continue;
        };
        modules.push(Module::new(entry, ModuleType::ElfModule, data));
    }
    modules
}

pub fn discover_modules_from_zfs(pools: &[ZfsPool], bootenv: &str) -> Vec<Module> {
    let mut modules = Vec::new();
    let Some((pool, dataset)) = zfs::find_pool_for_bootenv(pools, bootenv) else {
        return modules;
    };
    let entries = match zfs::fs::list_dir_from_bootenv(pool, &dataset, DEFAULT_KERNEL_DIR) {
        Ok(entries) => entries,
        Err(err) => {
            log::warn!("zfs module dir read failed: {}", err);
            return modules;
        }
    };
    for entry in entries {
        if !is_module_filename(&entry) {
            continue;
        }
        let path = format!("{}/{}", DEFAULT_KERNEL_DIR, entry);
        let data = match zfs::fs::read_file_from_bootenv(pool, &dataset, &path) {
            Ok(data) => data,
            Err(_) => continue,
        };
        modules.push(Module::new(entry, ModuleType::ElfModule, data));
    }
    modules
}

pub fn discover_modules_from_zfs_bootfs(pools: &[ZfsPool], pool_index: usize) -> Vec<Module> {
    let mut modules = Vec::new();
    let Some(pool) = pools.get(pool_index) else {
        return modules;
    };
    let block = match boot::open_protocol_exclusive::<BlockIO>(pool.handle) {
        Ok(block) => block,
        Err(err) => {
            log::warn!("zfs bootfs BlockIO open failed: {:?}", err.status());
            return modules;
        }
    };
    let Some(uber) = pool.uber else {
        log::warn!("zfs bootfs module dir read failed: uberblock missing");
        return modules;
    };
    let objset = match zfs::fs::bootfs_objset(&block, pool.media_id, pool.block_size, uber) {
        Ok(objset) => objset,
        Err(err) => {
            log::warn!("zfs bootfs module dir read failed: {}", err);
            return modules;
        }
    };
    let entries = match zfs::fs::list_dir_entries_with_ids(
        &block,
        pool.media_id,
        pool.block_size,
        &objset,
        DEFAULT_KERNEL_DIR,
    ) {
        Ok(entries) => entries,
        Err(err) => {
            log::warn!("zfs bootfs module dir read failed: {}", err);
            return modules;
        }
    };
    for (entry, objid) in entries {
        if !is_module_filename(&entry) {
            continue;
        }
        let data = match zfs::fs::read_file_from_objset_objid(
            &block,
            pool.media_id,
            pool.block_size,
            &objset,
            objid,
        ) {
            Ok(data) => data,
            Err(_) => continue,
        };
        modules.push(Module::new(entry, ModuleType::ElfModule, data));
    }
    modules
}

pub fn read_kernel_from_iso_devices(env: &LoaderEnv) -> Option<(IsoContext, Vec<u8>)> {
    let path = env.get("kernel").unwrap_or(DEFAULT_KERNEL_PATH);
    let handles = boot::locate_handle_buffer(SearchType::ByProtocol(&BlockIO::GUID)).ok()?;
    let mut logged = 0usize;
    for handle in handles.iter().copied() {
        let block = match boot::open_protocol_exclusive::<BlockIO>(handle) {
            Ok(block) => block,
            Err(err) => {
                if logged < 3 {
                    log::warn!("iso9660: BlockIO open failed: {:?}", err.status());
                    logged += 1;
                }
                continue;
            }
        };
        let media = block.media();
        if !media.is_media_present() {
            continue;
        }
        let block_size = media.block_size() as usize;
        let Some(volume) = iso9660::probe_iso9660(&block, media.media_id(), block_size) else {
            continue;
        };
        if let Some(bytes) =
            iso9660::read_file(&block, media.media_id(), block_size, volume, path)
        {
            let ctx = IsoContext {
                handle,
                media_id: media.media_id(),
                block_size,
                volume,
            };
            return Some((ctx, bytes));
        }
    }
    None
}

pub fn discover_modules_from_iso(ctx: &IsoContext) -> Vec<Module> {
    let mut modules = Vec::new();
    let block = match boot::open_protocol_exclusive::<BlockIO>(ctx.handle) {
        Ok(block) => block,
        Err(_) => return modules,
    };
    let Some(entries) =
        iso9660::read_dir_entries(&block, ctx.media_id, ctx.block_size, ctx.volume, DEFAULT_KERNEL_DIR)
    else {
        return modules;
    };
    for entry in entries {
        if !is_module_filename(&entry) {
            continue;
        }
        let path = format!("{}/{}", DEFAULT_KERNEL_DIR, entry);
        let Some(data) =
            iso9660::read_file(&block, ctx.media_id, ctx.block_size, ctx.volume, &path)
        else {
            continue;
        };
        modules.push(Module::new(entry, ModuleType::ElfModule, data));
    }
    modules
}

fn is_module_filename(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".ko")
}

#[allow(dead_code)]
pub fn build_kernel_modulep(image: &elf::LoadedKernelImage, modules: &[Module]) -> Option<Vec<u8>> {
    build_kernel_modulep_with_metadata(image.base, image.image.len() as u64, modules, None, None)
}

pub fn build_kernel_modulep_with_metadata(
    kernel_base: u64,
    kernel_size: u64,
    modules: &[Module],
    efi_map: Option<&[u8]>,
    envp: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let mut builder = ModulepBuilder::new();
    builder.add_name("kernel");
    builder.add_type(ModuleType::ElfKernel);
    builder.add_addr(kernel_base);
    builder.add_size(kernel_size);
    if let Some(map) = efi_map {
        if !map.is_empty() {
            builder.add_metadata_bytes(ModInfoMd::EfiMap, map);
        }
    }
    if let Some(ptr) = table::system_table_raw().map(|st| st.as_ptr() as u64) {
        builder.add_metadata_bytes(ModInfoMd::FwHandle, &ptr.to_le_bytes());
    }
    builder.add_metadata_bytes(ModInfoMd::EfiArch, b"amd64\0");
    if let Some(envp) = envp {
        if !envp.is_empty() {
            builder.add_metadata_bytes(ModInfoMd::Envp, envp);
        }
    }
    for module in modules {
        builder.add_module(module);
    }
    Some(builder.finish())
}

pub fn load_modules_to_memory(modules: &mut [Module]) -> Result<()> {
    for module in modules {
        if module.phys_addr.is_some() {
            continue;
        }
        if module.data.is_empty() {
            return Err(BootError::InvalidData("module data empty"));
        }
        let size = module.data.len();
        let pages = (size + uefi::boot::PAGE_SIZE - 1) / uefi::boot::PAGE_SIZE;
        let addr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
            .map_err(|err| BootError::Uefi(err.status()))?;
        let addr = addr.as_ptr() as u64;
        unsafe {
            let dst = addr as *mut u8;
            core::ptr::copy_nonoverlapping(module.data.as_ptr(), dst, size);
        }
        module.set_physical_address(addr);
    }
    Ok(())
}

pub fn build_envp(env: &LoaderEnv) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    push_env_vars(&mut bytes, &mut keys, &env.env_vars);
    push_env_vars(&mut bytes, &mut keys, &env.conf_vars);
    if bytes.last().copied() != Some(0) {
        bytes.push(0);
    }
    bytes.push(0);
    bytes
}

#[allow(dead_code)]
pub struct LoadedKernelImagePhys {
    pub base: u64,
    pub entry: u64,
    pub size: usize,
    pub info: elf::Elf64Info,
}

pub fn collect_efi_map_metadata() -> Result<Vec<u8>> {
    let memory_map =
        boot::memory_map(MemoryType::LOADER_DATA).map_err(|err| BootError::Uefi(err.status()))?;
    let meta = memory_map.meta();
    let buf = memory_map.buffer();
    build_efi_map_metadata_from_raw(meta.map_size, meta.desc_size, meta.desc_version, buf)
}

fn build_efi_map_metadata_from_raw(
    map_size: usize,
    desc_size: usize,
    desc_version: u32,
    buf: &[u8],
) -> Result<Vec<u8>> {
    if map_size == 0 || desc_size == 0 || map_size > buf.len() {
        return Err(BootError::InvalidData("EFI memory map invalid"));
    }
    let header_size = core::mem::size_of::<EfiMapHeader>();
    let header_aligned = (header_size + 15) & !15;
    let mut bytes = Vec::with_capacity(header_aligned + map_size);
    let header = EfiMapHeader {
        memory_size: map_size as u64,
        descriptor_size: desc_size as u64,
        descriptor_version: desc_version,
        pad: 0,
    };
    bytes.extend_from_slice(&header.memory_size.to_le_bytes());
    bytes.extend_from_slice(&header.descriptor_size.to_le_bytes());
    bytes.extend_from_slice(&header.descriptor_version.to_le_bytes());
    bytes.extend_from_slice(&header.pad.to_le_bytes());
    bytes.resize(header_aligned, 0);
    bytes.extend_from_slice(&buf[0..map_size]);
    Ok(bytes)
}

fn push_env_vars(bytes: &mut Vec<u8>, keys: &mut Vec<String>, vars: &[EnvVar]) {
    for var in vars {
        if keys.iter().any(|k| k == &var.key) {
            continue;
        }
        keys.push(var.key.clone());
        bytes.extend_from_slice(var.key.as_bytes());
        bytes.push(b'=');
        bytes.extend_from_slice(var.value.as_bytes());
        bytes.push(0);
    }
}

pub fn load_kernel_to_memory(image: &elf::LoadedKernelImage) -> Result<LoadedKernelImagePhys> {
    let size = image.image.len();
    if size == 0 {
        return Err(BootError::InvalidData("loaded kernel image empty"));
    }
    let pages = (size + uefi::boot::PAGE_SIZE - 1) / uefi::boot::PAGE_SIZE;
    let addr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let addr = addr.as_ptr() as u64;
    unsafe {
        let dst = addr as *mut u8;
        core::ptr::copy_nonoverlapping(image.image.as_ptr(), dst, size);
    }
    Ok(LoadedKernelImagePhys {
        base: addr,
        entry: image.entry,
        size,
        info: image.info.clone(),
    })
}

#[repr(C)]
struct EfiMapHeader {
    memory_size: u64,
    descriptor_size: u64,
    descriptor_version: u32,
    pad: u32,
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::string::ToString;

    use super::{build_envp, build_efi_map_metadata_from_raw, is_module_filename};
    use crate::env::loader::LoaderEnv;
    use crate::env::parser::EnvVar;

    #[test]
    fn test_build_efi_map_metadata_bytes() {
        let mut buf = alloc::vec![0u8; 64];
        buf[0] = 0xAA;
        let bytes = build_efi_map_metadata_from_raw(32, 48, 1, &buf).expect("bytes");
        assert!(bytes.len() >= 32 + 32);
        assert_eq!(bytes[0], 32);
        let payload = &bytes[32..64];
        assert_eq!(payload[0], 0xAA);
    }

    #[test]
    fn test_is_module_filename() {
        assert!(is_module_filename("foo.ko"));
        assert!(is_module_filename("BAR.KO"));
        assert!(!is_module_filename("kernel"));
        assert!(!is_module_filename("foo.ko.debug"));
    }

    #[test]
    fn test_build_envp_prefers_env_vars() {
        let env = LoaderEnv {
            env_vars: alloc::vec![EnvVar {
                key: "foo".to_string(),
                value: "1".to_string(),
            }],
            conf_vars: alloc::vec![EnvVar {
                key: "foo".to_string(),
                value: "2".to_string(),
            }, EnvVar {
                key: "bar".to_string(),
                value: "3".to_string(),
            }],
        };
        let envp = build_envp(&env);
        let text = core::str::from_utf8(&envp).expect("utf8");
        assert!(text.contains("foo=1\0"));
        assert!(text.contains("bar=3\0"));
        assert!(text.ends_with("\0\0"));
        assert!(!text.contains("foo=2\0"));
    }
}
