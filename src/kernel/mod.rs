extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::env::loader::LoaderEnv;
use crate::env::parser::EnvVar;
use crate::fs::uefi::{
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
use crate::uefi_helpers::block_io::open_block_io;
use crate::kernel::modulep::ModulepBuilder;
use crate::kernel::types::{ModInfoMd, ModuleType};
use crate::error::{BootError, Result};
use uefi::mem::memory_map::MemoryMap;
use uefi::table;

pub mod elf;
pub mod module;
pub mod modulep;
pub mod types;

#[allow(dead_code)]
const DEFAULT_KERNEL_PATH: &str = "/boot/kernel/kernel";
const DEFAULT_KERNEL_DIR: &str = "/boot/kernel";
pub const KERNEL_PHYS_BASE: u64 = 0x20_0000;

fn normalize_kernel_path(path: &str) -> String {
    let mut out = path.replace('\\', "/");
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    out
}

struct ModuleSpec {
    name: String,
    type_: Option<String>,
    flags: Option<String>,
    before: Option<String>,
    after: Option<String>,
    error: Option<String>,
}

pub fn load_preload_modules_with<F>(env: &mut LoaderEnv, read_file: F) -> Vec<Module>
where
    F: Fn(&str) -> Option<Vec<u8>>,
{
    load_preload_modules_with_reader(
        env,
        |path: String| read_file(path.as_str()),
        None::<fn(String) -> Option<(u64, usize)>>,
    )
}

pub fn load_preload_modules_with_reader<F, S>(
    env: &mut LoaderEnv,
    read_file: F,
    stream_raw: Option<S>,
) -> Vec<Module>
where
    F: Fn(String) -> Option<Vec<u8>>,
    S: Fn(String) -> Option<(u64, usize)>,
{
    let merged = merged_env(env);
    let module_path = merged.get("module_path").map(String::as_str);
    let specs = collect_module_specs(&merged);
    let mut modules = Vec::new();
    for spec in specs {
        let is_optional = matches!(
            spec.type_.as_deref(),
            Some("boot_entropy_cache") | Some("hostuuid") | Some("ram_blacklist")
        );
        if let Some(cmd) = spec.before.as_deref() {
            run_module_command(cmd, env);
        }
        let (module_type, is_kld) = module_type_for_load(spec.type_.as_deref());
        let candidates = module_path_candidates(&spec.name, module_path, is_kld);
        let mut loaded = false;
        for path in candidates {
            if matches!(module_type, ModuleType::Raw(ref t) if t == "mfs_root") {
                if let Some(ref loader) = stream_raw {
                    if let Some((addr, size)) = loader(path.clone()) {
                        log::info!("module: {} type={} bytes={}", path, module_type, size);
                        let module = Module::from_phys(
                            path,
                            module_type.clone(),
                            addr,
                            size,
                            spec.flags.clone(),
                        );
                        modules.push(module);
                        loaded = true;
                        break;
                    }
                }
            }
            if let Some(bytes) = read_file(path.clone()) {
                log::info!(
                    "module: {} type={} bytes={}",
                    path,
                    module_type,
                    bytes.len()
                );
                let mut module = Module::new(path, module_type.clone(), bytes);
                if let Some(flags) = spec.flags.clone().filter(|s| !s.is_empty()) {
                    module.set_args(Some(flags));
                }
                modules.push(module);
                loaded = true;
                break;
            }
        }
        if loaded {
            if let Some(cmd) = spec.after.as_deref() {
                run_module_command(cmd, env);
            }
        } else if let Some(cmd) = spec.error.as_deref() {
            run_module_command(cmd, env);
        } else if !is_optional {
            log::warn!(
                "module load failed: {} (type={})",
                spec.name,
                module_type
            );
        }
    }
    modules
}

fn merged_env(env: &mut LoaderEnv) -> BTreeMap<String, String> {
    let mut merged = BTreeMap::<String, String>::new();
    for var in &env.conf_vars {
        merged.insert(var.key.clone(), var.value.clone());
    }
    for var in &env.env_vars {
        merged.insert(var.key.clone(), var.value.clone());
    }
    if let Some(value) = merged.get("mfs_load").map(String::as_str) {
        if is_truthy(value) && !merged.contains_key("mfsroot_load") {
            let name = merged
                .get("mfs_name")
                .cloned()
                .unwrap_or_else(|| "/mfsroot".to_string());
            let type_ = merged
                .get("mfs_type")
                .cloned()
                .unwrap_or_else(|| "mfs_root".to_string());
            merged.insert("mfsroot_load".to_string(), "YES".to_string());
            merged.insert("mfsroot_name".to_string(), name);
            merged.insert("mfsroot_type".to_string(), type_);
        }
    }
    let kernel_dir = kernel_dir_from_env(env);
    let module_path = merged.get("module_path").cloned();
    let effective_module_path = match module_path {
        Some(path) => {
            if module_path_contains(&path, &kernel_dir) {
                path
            } else {
                format!("{};{}", kernel_dir, path)
            }
        }
        None => kernel_dir.clone(),
    };
    merged.insert("module_path".to_string(), effective_module_path.clone());
    if env.get("module_path") != Some(effective_module_path.as_str()) {
        env.set("module_path", &effective_module_path);
    }
    merged
}

fn module_path_contains(path_list: &str, entry: &str) -> bool {
    let target = normalize_kernel_path(entry);
    for raw in path_list.split(';') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let normalized = normalize_kernel_path(raw);
        if normalized.trim_end_matches('/') == target.trim_end_matches('/') {
            return true;
        }
    }
    false
}

fn collect_module_specs(merged: &BTreeMap<String, String>) -> Vec<ModuleSpec> {
    let mut specs = Vec::new();
    for (key, value) in merged {
        if !key.ends_with("_load") || !is_truthy(value) {
            continue;
        }
        let prefix = &key[..key.len() - "_load".len()];
        if prefix.is_empty() {
            continue;
        }
        let name = get_prefixed_value(merged, prefix, &["_name"])
            .unwrap_or_else(|| prefix.to_string());
        let spec = ModuleSpec {
            name,
            type_: get_prefixed_value(merged, prefix, &["_type"]),
            flags: get_prefixed_value(merged, prefix, &["_args", "_flags"]),
            before: get_prefixed_value(merged, prefix, &["_beforeload", "_before"]),
            after: get_prefixed_value(merged, prefix, &["_afterload", "_after"]),
            error: get_prefixed_value(merged, prefix, &["_loaderror", "_error"]),
        };
        specs.push(spec);
    }
    specs
}

fn get_prefixed_value(
    merged: &BTreeMap<String, String>,
    prefix: &str,
    suffixes: &[&str],
) -> Option<String> {
    for suffix in suffixes {
        let key = format!("{}{}", prefix, suffix);
        if let Some(value) = merged.get(&key) {
            return Some(value.clone());
        }
    }
    None
}

fn module_type_for_load(type_opt: Option<&str>) -> (ModuleType, bool) {
    let type_opt = type_opt.map(str::trim).filter(|t| !t.is_empty());
    match type_opt {
        None => (ModuleType::ElfModule, true),
        Some(type_) if type_.eq_ignore_ascii_case("kld") => (ModuleType::ElfModule, true),
        Some(type_) if type_.eq_ignore_ascii_case("elf module") => (ModuleType::ElfModule, true),
        Some(type_) if type_.eq_ignore_ascii_case("elf obj") => (ModuleType::ElfObj, true),
        Some(type_) if type_.eq_ignore_ascii_case("elf kernel") => (ModuleType::ElfKernel, false),
        Some(type_) => (ModuleType::Raw(type_.to_string()), false),
    }
}

fn module_path_candidates(name: &str, module_path: Option<&str>, is_kld: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut add_candidate = |path: String| {
        if !out.contains(&path) {
            out.push(path);
        }
    };
    if name.contains('/') || name.contains('\\') {
        add_candidate(normalize_kernel_path(name));
        return out;
    }
    let mut names = Vec::new();
    if is_kld && !name.to_ascii_lowercase().ends_with(".ko") {
        names.push(format!("{}.ko", name));
    }
    names.push(name.to_string());
    if let Some(path_list) = module_path {
        for entry in path_list.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let base = normalize_kernel_path(entry);
            let base = base.trim_end_matches('/');
            for name in &names {
                add_candidate(format!("{}/{}", base, name));
            }
        }
    } else {
        for name in &names {
            add_candidate(format!("/boot/kernel/{}", name));
        }
    }
    out
}

fn run_module_command(cmd: &str, env: &mut LoaderEnv) {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return;
    }
    if let Some(rest) = cmd.strip_prefix("set ") {
        if let Some((key, value)) = split_key_value_exec(rest.trim()) {
            env.set(&key, &value);
        } else {
            log::warn!("module cmd: invalid set syntax: {}", cmd);
        }
        return;
    }
    if let Some(rest) = cmd.strip_prefix("unset ") {
        let key = rest.trim();
        if !key.is_empty() {
            env.unset(key);
        }
        return;
    }
    if let Some(rest) = cmd.strip_prefix("echo ") {
        log::info!("{}", rest.trim());
        return;
    }
    log::warn!("module cmd: ignored command: {}", cmd);
}

fn split_key_value_exec(input: &str) -> Option<(String, String)> {
    let idx = input.find('=')?;
    let key = input[..idx].trim();
    if key.is_empty() {
        return None;
    }
    let mut value = input[idx + 1..].trim().to_string();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    } else if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    }
    Some((key.to_string(), value))
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value,
        "1" | "YES" | "yes" | "true" | "TRUE" | "on" | "ON"
    )
}

fn kernel_path_from_env(env: &LoaderEnv) -> String {
    let kernel = env.get("kernel").unwrap_or(DEFAULT_KERNEL_DIR);
    if kernel.contains('/') || kernel.contains('\\') {
        return normalize_kernel_path(kernel);
    }
    let bootfile = env.get("bootfile").unwrap_or("kernel");
    if bootfile.contains('/') || bootfile.contains('\\') {
        return normalize_kernel_path(bootfile);
    }
    format!("/boot/{}/{}", kernel, bootfile)
}

fn kernel_dir_from_env(env: &LoaderEnv) -> String {
    let kernel = env.get("kernel").unwrap_or(DEFAULT_KERNEL_DIR);
    if kernel.contains('/') || kernel.contains('\\') {
        let path = normalize_kernel_path(kernel);
        let trimmed = path.trim_end_matches('/');
        if let Some(pos) = trimmed.rfind('/') {
            if pos == 0 {
                return "/".to_string();
            }
            return trimmed[..pos].to_string();
        }
        return DEFAULT_KERNEL_DIR.to_string();
    }
    format!("/boot/{}", kernel)
}

pub struct IsoContext {
    handle: uefi::Handle,
    media_id: u32,
    block_size: usize,
    volume: IsoVolume,
}

pub fn read_kernel_from_currdev(guid: [u8; 16], env: &LoaderEnv) -> Option<Vec<u8>> {
    let path = kernel_path_from_env(env);
    read_file_from_partition_guid(guid, &path)
}

pub fn read_kernel_from_boot_volume(env: &LoaderEnv) -> Option<Vec<u8>> {
    let path = kernel_path_from_env(env);
    let bytes = read_file_from_boot_volume(&path);
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
    let path = kernel_path_from_env(env);
    match zfs::fs::read_file_from_bootenv(pool, &dataset, &path) {
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
    let path = kernel_path_from_env(env);
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
        match zfs::fs::read_file_from_objset(&block, pool.media_id, pool.block_size, &objset, &path)
        {
            Ok(bytes) => return Some((idx, bytes)),
            Err(err) => {
                log::warn!("zfs bootfs kernel read failed: {}", err);
            }
        }
    }
    None
}

pub fn discover_modules_from_currdev(guid: [u8; 16], env: &mut LoaderEnv) -> Vec<Module> {
    load_preload_modules_with(env, |path| read_file_from_partition_guid(guid, path))
}

pub fn discover_modules_from_boot_volume(env: &mut LoaderEnv) -> Vec<Module> {
    load_preload_modules_with_reader(
        env,
        |path: String| read_file_from_boot_volume(&path).or_else(|| read_file_from_iso_devices(&path)),
        Some(|path: String| {
            let size = crate::fs::uefi::file_size_from_boot_volume(&path)?;
            let pages = (size + uefi::boot::PAGE_SIZE - 1) / uefi::boot::PAGE_SIZE;
            let addr = boot::allocate_pages(
                AllocateType::MaxAddress(0x7fff_ffff),
                MemoryType::LOADER_DATA,
                pages,
            )
            .ok()?
            .as_ptr() as u64;
            let ok = crate::fs::uefi::read_file_from_boot_volume_into(
                &path,
                addr as *mut u8,
                size,
            )
            .is_some();
            if ok { Some((addr, size)) } else { None }
        }),
    )
}

pub fn discover_modules_from_zfs(
    pools: &[ZfsPool],
    bootenv: &str,
    env: &mut LoaderEnv,
) -> Vec<Module> {
    let Some((pool, dataset)) = zfs::find_pool_for_bootenv(pools, bootenv) else {
        return Vec::new();
    };
    load_preload_modules_with(env, |path| {
        zfs::fs::read_file_from_bootenv(pool, &dataset, path).ok()
    })
}

pub fn discover_modules_from_zfs_bootfs(
    pools: &[ZfsPool],
    pool_index: usize,
    env: &mut LoaderEnv,
) -> Vec<Module> {
    let Some(pool) = pools.get(pool_index) else {
        return Vec::new();
    };
    let block = match boot::open_protocol_exclusive::<BlockIO>(pool.handle) {
        Ok(block) => block,
        Err(err) => {
            log::warn!("zfs bootfs BlockIO open failed: {:?}", err.status());
            return Vec::new();
        }
    };
    let Some(uber) = pool.uber else {
        log::warn!("zfs bootfs module dir read failed: uberblock missing");
        return Vec::new();
    };
    let objset = match zfs::fs::bootfs_objset(&block, pool.media_id, pool.block_size, uber) {
        Ok(objset) => objset,
        Err(err) => {
            log::warn!("zfs bootfs module dir read failed: {}", err);
            return Vec::new();
        }
    };
    load_preload_modules_with(env, |path| {
        zfs::fs::read_file_from_objset(&block, pool.media_id, pool.block_size, &objset, path).ok()
    })
}

pub fn read_kernel_from_iso_devices(env: &LoaderEnv) -> Option<(IsoContext, Vec<u8>)> {
    let path = kernel_path_from_env(env);
    log::info!("iso9660: probing kernel path {}", path);
    let handles = boot::locate_handle_buffer(SearchType::ByProtocol(&BlockIO::GUID)).ok()?;
    log::info!("iso9660: {} block handles", handles.len());
    let mut logged = 0usize;
    for handle in handles.iter().copied() {
        let block = match open_block_io(handle) {
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
            iso9660::read_file(&block, media.media_id(), block_size, volume, &path)
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

pub fn read_kernel_from_iso_handle(handle: uefi::Handle, env: &LoaderEnv) -> Option<(IsoContext, Vec<u8>)> {
    let path = kernel_path_from_env(env);
    let block = match open_block_io(handle) {
        Ok(block) => block,
        Err(err) => {
            log::warn!("iso9660: BlockIO open failed: {:?}", err.status());
            return None;
        }
    };
    let media = block.media();
    log::info!(
        "iso9660: media id={} block_size={} io_align={} removable={} ro={}",
        media.media_id(),
        media.block_size(),
        media.io_align(),
        media.is_removable_media(),
        media.is_read_only()
    );
    if !media.is_media_present() {
        return None;
    }
    let block_size = media.block_size() as usize;
    let Some(volume) = iso9660::probe_iso9660(&block, media.media_id(), block_size) else {
        log::warn!("iso9660: probe failed for media id {}", media.media_id());
        return None;
    };
    let bytes = match iso9660::read_file(&block, media.media_id(), block_size, volume, &path) {
        Some(bytes) => bytes,
        None => {
            log::warn!("iso9660: kernel not found at {}", path);
            return None;
        }
    };
    let ctx = IsoContext {
        handle,
        media_id: media.media_id(),
        block_size,
        volume,
    };
    Some((ctx, bytes))
}

pub fn read_file_from_iso_devices(path: &str) -> Option<Vec<u8>> {
    let handles = boot::locate_handle_buffer(SearchType::ByProtocol(&BlockIO::GUID)).ok()?;
    let mut logged = 0usize;
    for handle in handles.iter().copied() {
        let block = match open_block_io(handle) {
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
        if let Some(bytes) = iso9660::read_file(&block, media.media_id(), block_size, volume, path)
        {
            return Some(bytes);
        }
    }
    None
}

pub fn discover_modules_from_iso(ctx: &IsoContext, env: &mut LoaderEnv) -> Vec<Module> {
    let block = match open_block_io(ctx.handle) {
        Ok(block) => block,
        Err(_) => return Vec::new(),
    };
    load_preload_modules_with_reader(
        env,
        |path: String| iso9660::read_file(&block, ctx.media_id, ctx.block_size, ctx.volume, &path),
        Some(|path: String| {
            let size =
                iso9660::file_size(&block, ctx.media_id, ctx.block_size, ctx.volume, &path)?;
            let pages = (size + uefi::boot::PAGE_SIZE - 1) / uefi::boot::PAGE_SIZE;
            let addr = boot::allocate_pages(
                AllocateType::MaxAddress(0x7fff_ffff),
                MemoryType::LOADER_DATA,
                pages,
            )
            .ok()?
            .as_ptr() as u64;
            let ok = iso9660::read_file_into(
                &block,
                ctx.media_id,
                ctx.block_size,
                ctx.volume,
                &path,
                addr as *mut u8,
                size,
            )
            .is_some();
            if ok { Some((addr, size)) } else { None }
        }),
    )
}

#[cfg(test)]
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

pub fn build_kernel_modulep_with_metadata_relocated(
    kernel_base: u64,
    kernel_size: u64,
    modules: &[Module],
    efi_map: Option<&[u8]>,
    envp_phys: Option<u64>,
    phys_base: u64,
    modulep_offset: u64,
    kernend_offset: u64,
    howto: u32,
) -> Option<Vec<u8>> {
    if kernel_base < phys_base {
        log::warn!("kernel base below phys_base for modulep relocation");
        return None;
    }
    let mut builder = ModulepBuilder::new();
    builder.add_name("kernel");
    builder.add_type(ModuleType::ElfKernel);
    builder.add_addr(kernel_base - phys_base);
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
    // ENVP: the kernel expects a *pointer* to the env string, not the
    // string content.  The caller stages the env bytes separately and
    // passes the physical address here.
    if let Some(addr) = envp_phys {
        builder.add_metadata_u64(ModInfoMd::Envp, addr);
    }
    builder.add_metadata_u64(ModInfoMd::Modulep, modulep_offset);
    builder.add_metadata_u64(ModInfoMd::Kernend, kernend_offset);
    if howto != 0 {
        builder.add_metadata_u32(ModInfoMd::Howto, howto);
    }
    for module in modules {
        if let Some(addr) = module.phys_addr {
            if addr < phys_base {
                log::warn!("module {} below phys_base; skipping", module.name);
                continue;
            }
            builder.add_name(&module.name);
            builder.add_type(module.module_type.clone());
            builder.add_addr(addr - phys_base);
            builder.add_size(module.data_len as u64);
            if let Some(args) = module.args.as_deref() {
                builder.add_args(args);
            }
        }
    }
    Some(builder.finish())
}

pub fn load_modules_to_memory(modules: &mut [Module]) -> Result<()> {
    for module in modules {
        if module.phys_addr.is_some() {
            continue;
        }
        if module.data_len == 0 || module.data.is_empty() {
            return Err(BootError::InvalidData("module data empty"));
        }
        let size = module.data_len;
        let pages = (size + uefi::boot::PAGE_SIZE - 1) / uefi::boot::PAGE_SIZE;
        let addr = boot::allocate_pages(
            AllocateType::MaxAddress(0x7fff_ffff),
            MemoryType::LOADER_DATA,
            pages,
        )
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

pub fn patch_headless_vga(
    image: &mut elf::LoadedKernelImage,
    kernel_bytes: &[u8],
    env: &LoaderEnv,
) {
    let trial = matches!(
        env.get("zhamel_trial"),
        Some("1") | Some("YES") | Some("yes") | Some("true")
    );
    if !trial {
        return;
    }
    let gop_present = matches!(env.get("zhamel.gop_present"), Some("1"));
    if gop_present {
        return;
    }
    if matches!(env.get("secureboot"), Some("1")) {
        log::warn!("vga: headless patch skipped (secureboot enabled)");
        return;
    }
    let patch: [u8; 6] = [0xb8, 0x06, 0x00, 0x00, 0x00, 0xc3]; // mov $ENXIO,%eax; ret
    let mut patched = false;
    for name in ["vga_probe_unit", "verify_adapter"] {
        let Some(addr) = image.info.symbol_addr(kernel_bytes, name) else {
            continue;
        };
        let Some(off) = image
            .info
            .addr_to_offset(image.base, image.image.len(), addr)
        else {
            continue;
        };
        let off = off as usize;
        if off + patch.len() > image.image.len() {
            continue;
        }
        image.image[off..off + patch.len()].copy_from_slice(&patch);
        log::warn!("vga: patched {} to return ENXIO (headless)", name);
        patched = true;
        break;
    }
    if !patched {
        log::warn!("vga: headless patch not applied (symbol missing?)");
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

pub fn load_kernel_to_memory_at(
    image: &elf::LoadedKernelImage,
    base: u64,
) -> Result<LoadedKernelImagePhys> {
    let size = image.image.len();
    if size == 0 {
        return Err(BootError::InvalidData("loaded kernel image empty"));
    }
    let pages = (size + uefi::boot::PAGE_SIZE - 1) / uefi::boot::PAGE_SIZE;
    let addr = boot::allocate_pages(AllocateType::Address(base), MemoryType::LOADER_DATA, pages)
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
