extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::env::loader::LoaderEnv;
use crate::env::parser::EnvVar;
use crate::error::{BootError, Result};
use crate::fs::iso9660::{self, IsoVolume};
use crate::fs::uefi::{read_file_from_boot_volume, read_file_from_partition_guid};
use crate::kernel::module::Module;
use crate::kernel::modulep::ModulepBuilder;
use crate::kernel::types::{ModInfoMd, ModuleType};
use crate::uefi_helpers::block_io::open_block_io;
use crate::zfs;
use crate::zfs::ZfsPool;
use uefi::Identify;
use uefi::boot::{self, AllocateType, MemoryType, SearchType};
use uefi::mem::memory_map::MemoryMap;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::media::block::BlockIO;
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
    let mut specs = collect_module_specs(&merged);
    sort_module_specs(&mut specs);
    log::info!(
        "module discovery: specs={} module_path={}",
        specs.len(),
        module_path.unwrap_or("<default>")
    );
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
        log::info!(
            "module discovery: spec name={} type={} candidates={}",
            spec.name,
            module_type,
            candidates.join(",")
        );
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
            log::warn!("module load failed: {} (type={})", spec.name, module_type);
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
        let name =
            get_prefixed_value(merged, prefix, &["_name"]).unwrap_or_else(|| prefix.to_string());
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

fn sort_module_specs(specs: &mut [ModuleSpec]) {
    specs.sort_by(|left, right| {
        module_spec_priority(left)
            .cmp(&module_spec_priority(right))
            .then_with(|| left.name.cmp(&right.name))
    });
}

fn module_spec_priority(spec: &ModuleSpec) -> u8 {
    match module_spec_basename(&spec.name) {
        "opensolaris" => 10,
        "xdr" => 20,
        "acl_nfs4" => 30,
        "crypto" => 40,
        "zlib" => 50,
        "zfs" => 60,
        "zhamel_zfskey" => 70,
        _ => 100,
    }
}

fn module_spec_basename(name: &str) -> &str {
    let slash = name.rfind('/');
    let backslash = name.rfind('\\');
    let start = match (slash, backslash) {
        (Some(a), Some(b)) => core::cmp::max(a, b) + 1,
        (Some(idx), None) | (None, Some(idx)) => idx + 1,
        (None, None) => 0,
    };
    let name = &name[start..];
    name.strip_suffix(".ko").unwrap_or(name)
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
        None => (ModuleType::ElfObj, true),
        Some(type_) if type_.eq_ignore_ascii_case("kld") => (ModuleType::ElfObj, true),
        Some(type_) if type_.eq_ignore_ascii_case("elf module") => (ModuleType::ElfModule, true),
        Some(type_)
            if type_.eq_ignore_ascii_case("elf obj")
                || type_.eq_ignore_ascii_case("elf obj module") =>
        {
            (ModuleType::ElfObj, true)
        }
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
    matches!(value, "1" | "YES" | "yes" | "true" | "TRUE" | "on" | "ON")
}

fn kernel_path_from_env(env: &LoaderEnv) -> String {
    let kernel = env.get("kernel").unwrap_or("kernel");
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

#[derive(Clone, Debug)]
pub enum ZfsReadSource {
    Bootfs,
    Dataset(String),
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

pub fn read_kernel_from_zfs(pools: &[ZfsPool], bootenv: &str, env: &LoaderEnv) -> Option<Vec<u8>> {
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
) -> Option<(usize, ZfsReadSource, Vec<u8>)> {
    let path = kernel_path_from_env(env);
    for (idx, pool) in pools.iter().enumerate() {
        log::info!("zfs boot dataset kernel probe: pool {}", idx);
        if let Some((dataset, dataset_path, bytes)) =
            read_kernel_from_zfs_boot_dataset(pool, env, &path)
        {
            log::info!(
                "zfs boot dataset kernel read ok: dataset={} path={}",
                dataset,
                dataset_path
            );
            return Some((idx, ZfsReadSource::Dataset(dataset), bytes));
        }
        log::info!("zfs bootfs kernel probe: pool {}", idx);
        if let Some(bytes) = read_kernel_from_zfs_bootfs_dataset(pool, &path) {
            return Some((idx, ZfsReadSource::Bootfs, bytes));
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
        |path: String| {
            read_file_from_boot_volume(&path).or_else(|| read_file_from_iso_devices(&path))
        },
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
            let ok = crate::fs::uefi::read_file_from_boot_volume_into(&path, addr as *mut u8, size)
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
    source: &ZfsReadSource,
    env: &mut LoaderEnv,
) -> Vec<Module> {
    let Some(pool) = pools.get(pool_index) else {
        return Vec::new();
    };
    if let ZfsReadSource::Dataset(dataset) = source {
        return load_preload_modules_with(env, |path| {
            for dataset_path in paths_for_zfs_boot_dataset(path) {
                if let Ok(bytes) = zfs::fs::read_file_from_bootenv(pool, dataset, &dataset_path) {
                    return Some(bytes);
                }
            }
            None
        });
    }
    let block = match open_block_io(pool.handle) {
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

pub fn reload_loader_conf_from_zfs_bootfs(
    pools: &[ZfsPool],
    pool_index: usize,
    source: &ZfsReadSource,
    env: &mut LoaderEnv,
) {
    let Some(pool) = pools.get(pool_index) else {
        return;
    };
    let conf_vars = match source {
        ZfsReadSource::Dataset(dataset) => crate::env::loader::load_loader_conf_with(
            &env.env_vars,
            |path| {
                for dataset_path in paths_for_zfs_boot_dataset(path) {
                    if let Ok(bytes) = zfs::fs::read_file_from_bootenv(pool, dataset, &dataset_path)
                    {
                        return Some(bytes);
                    }
                }
                None
            },
            |path| {
                for dataset_path in paths_for_zfs_boot_dataset(path) {
                    if let Ok(entries) =
                        zfs::fs::list_dir_from_bootenv(pool, dataset, &dataset_path)
                    {
                        return Some(entries);
                    }
                }
                None
            },
        ),
        ZfsReadSource::Bootfs => {
            let block = match open_block_io(pool.handle) {
                Ok(block) => block,
                Err(err) => {
                    log::warn!(
                        "zfs bootfs loader.conf BlockIO open failed: {:?}",
                        err.status()
                    );
                    return;
                }
            };
            let Some(uber) = pool.uber else {
                log::warn!("zfs bootfs loader.conf read failed: uberblock missing");
                return;
            };
            let objset = match zfs::fs::bootfs_objset(&block, pool.media_id, pool.block_size, uber)
            {
                Ok(objset) => objset,
                Err(err) => {
                    log::warn!("zfs bootfs loader.conf read failed: {}", err);
                    return;
                }
            };
            crate::env::loader::load_loader_conf_with(
                &env.env_vars,
                |path| {
                    zfs::fs::read_file_from_objset(
                        &block,
                        pool.media_id,
                        pool.block_size,
                        &objset,
                        path,
                    )
                    .ok()
                },
                |path| {
                    zfs::fs::list_dir_from_objset(
                        &block,
                        pool.media_id,
                        pool.block_size,
                        &objset,
                        path,
                    )
                    .ok()
                },
            )
        }
    };
    if conf_vars.is_empty() {
        log::warn!("zfs loader.conf not found for kernel source");
        return;
    }
    log::info!("zfs loader.conf reloaded: {} vars", conf_vars.len());
    env.conf_vars = conf_vars;
}

fn read_kernel_from_zfs_boot_dataset(
    pool: &ZfsPool,
    env: &LoaderEnv,
    kernel_path: &str,
) -> Option<(String, String, Vec<u8>)> {
    let dataset_paths = paths_for_zfs_boot_dataset(kernel_path);
    for dataset in zfs_boot_dataset_candidates(pool, env) {
        for dataset_path in &dataset_paths {
            match zfs::fs::read_file_from_bootenv(pool, &dataset, dataset_path) {
                Ok(bytes) => return Some((dataset, dataset_path.clone(), bytes)),
                Err(err) => {
                    log::warn!(
                        "zfs boot dataset kernel read failed: dataset={} path={} err={}",
                        dataset,
                        dataset_path,
                        err
                    );
                    log_zfs_boot_dataset_dir(pool, &dataset, dataset_path);
                }
            }
        }
    }
    None
}

fn log_zfs_boot_dataset_dir(pool: &ZfsPool, dataset: &str, path: &str) {
    let dir = path
        .trim_end_matches('/')
        .rsplit_once('/')
        .map(|(dir, _)| if dir.is_empty() { "/" } else { dir })
        .unwrap_or("/");
    match zfs::fs::list_dir_from_bootenv(pool, dataset, dir) {
        Ok(entries) => {
            log::info!(
                "zfs boot dataset dir: dataset={} dir={} entries={}",
                dataset,
                dir,
                entries.join(",")
            );
        }
        Err(err) => {
            log::warn!(
                "zfs boot dataset dir read failed: dataset={} dir={} err={}",
                dataset,
                dir,
                err
            );
        }
    }
}

fn read_kernel_from_zfs_bootfs_dataset(pool: &ZfsPool, path: &str) -> Option<Vec<u8>> {
    let block = match open_block_io(pool.handle) {
        Ok(block) => block,
        Err(err) => {
            log::warn!("zfs bootfs BlockIO open failed: {:?}", err.status());
            return None;
        }
    };
    let Some(uber) = pool.uber else {
        log::warn!("zfs bootfs kernel read failed: uberblock missing");
        return None;
    };
    let objset = match zfs::fs::bootfs_objset(&block, pool.media_id, pool.block_size, uber) {
        Ok(objset) => objset,
        Err(err) => {
            log::warn!("zfs bootfs kernel read failed: {}", err);
            return None;
        }
    };
    match zfs::fs::read_file_from_objset(&block, pool.media_id, pool.block_size, &objset, path) {
        Ok(bytes) => Some(bytes),
        Err(err) => {
            log::warn!("zfs bootfs kernel read failed: {}", err);
            None
        }
    }
}

fn zfs_boot_dataset_candidates(pool: &ZfsPool, env: &LoaderEnv) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(dataset) = env.get("zfs_boot_dataset") {
        push_boot_dataset_candidate(&mut out, pool, dataset);
    }
    match zfs::fs::datasets_for_mountpoint(pool, "/boot") {
        Ok(datasets) if datasets.is_empty() => {
            log::warn!("zfs boot dataset not found by mountpoint=/boot");
        }
        Ok(datasets) => {
            for dataset in datasets {
                push_boot_dataset_candidate(&mut out, pool, &dataset);
            }
        }
        Err(err) => {
            log::warn!("zfs boot dataset mountpoint lookup failed: {}", err);
        }
    }
    out
}

fn push_boot_dataset_candidate(out: &mut Vec<String>, pool: &ZfsPool, candidate: &str) {
    let mut value = candidate.trim().trim_end_matches(':');
    if let Some(stripped) = value.strip_prefix("zfs:") {
        value = stripped;
    }
    if let Some(name) = pool.name.as_deref() {
        if let Some(stripped) = value.strip_prefix(name) {
            value = stripped.trim_start_matches('/');
        }
    }
    if value.is_empty() || out.iter().any(|existing| existing == value) {
        return;
    }
    out.push(value.to_string());
}

fn paths_for_zfs_boot_dataset(path: &str) -> Vec<String> {
    let primary = path_for_zfs_boot_dataset(path);
    let fallback = normalize_kernel_path(path);
    if primary == fallback {
        return vec![primary];
    }
    vec![primary, fallback]
}

fn path_for_zfs_boot_dataset(path: &str) -> String {
    let normalized = normalize_kernel_path(path);
    if normalized == "/boot" {
        return "/".to_string();
    }
    if let Some(stripped) = normalized.strip_prefix("/boot/") {
        return format!("/{}", stripped);
    }
    normalized
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
        if let Some(bytes) = iso9660::read_file(&block, media.media_id(), block_size, volume, &path)
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

pub fn read_kernel_from_iso_handle(
    handle: uefi::Handle,
    env: &LoaderEnv,
) -> Option<(IsoContext, Vec<u8>)> {
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
            let size = iso9660::file_size(&block, ctx.media_id, ctx.block_size, ctx.volume, &path)?;
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
    build_kernel_modulep_with_metadata(
        image.base,
        image.image.len() as u64,
        modules,
        None,
        None,
        None,
    )
}

pub fn build_kernel_modulep_with_metadata(
    kernel_base: u64,
    kernel_size: u64,
    modules: &[Module],
    efi_map: Option<&[u8]>,
    efi_fb: Option<&[u8]>,
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
    if let Some(fb) = efi_fb {
        if !fb.is_empty() {
            builder.add_metadata_bytes(ModInfoMd::EfiFb, fb);
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
    efi_fb: Option<&[u8]>,
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
    if let Some(fb) = efi_fb {
        if !fb.is_empty() {
            builder.add_metadata_bytes(ModInfoMd::EfiFb, fb);
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
            if let Some(header) = module.elf_header.as_ref() {
                builder.add_metadata_bytes(ModInfoMd::Elfhdr, header);
            }
            if !module.section_headers.is_empty() {
                match relocated_elf_obj_section_headers(module, addr - phys_base) {
                    Ok(shdr) => builder.add_metadata_bytes(ModInfoMd::Shdr, &shdr),
                    Err(err) => {
                        log::warn!("module {} section metadata invalid: {}", module.name, err);
                        continue;
                    }
                }
            }
            if let Some(args) = module.args.as_deref() {
                builder.add_args(args);
            }
        }
    }
    Some(builder.finish())
}

#[allow(dead_code)]
pub fn load_modules_to_memory(modules: &mut [Module]) -> Result<()> {
    load_modules_to_memory_with_base(modules, None).map(|_| ())
}

pub fn load_modules_to_memory_at(modules: &mut [Module], base: u64) -> Result<u64> {
    load_modules_to_memory_with_base(modules, Some(base))
}

pub fn prepare_modules_for_handoff(modules: &mut [Module]) -> Result<()> {
    for module in modules {
        if matches!(module.module_type, ModuleType::ElfObj) && module.elf_header.is_none() {
            prepare_elf_obj_module(module)?;
        }
    }
    Ok(())
}

fn load_modules_to_memory_with_base(
    modules: &mut [Module],
    mut next_base: Option<u64>,
) -> Result<u64> {
    for module in modules {
        if module.phys_addr.is_some() {
            continue;
        }
        if module.data_len == 0 || module.data.is_empty() {
            return Err(BootError::InvalidData("module data empty"));
        }
        if matches!(module.module_type, ModuleType::ElfObj) && module.elf_header.is_none() {
            prepare_elf_obj_module(module)?;
        }
        let size = module.data_len;
        let pages = (size + uefi::boot::PAGE_SIZE - 1) / uefi::boot::PAGE_SIZE;
        let alloc = if let Some(base) = next_base {
            AllocateType::Address(page_align(base))
        } else {
            AllocateType::MaxAddress(0x7fff_ffff)
        };
        let addr = boot::allocate_pages(alloc, MemoryType::LOADER_DATA, pages)
            .map_err(|err| BootError::Uefi(err.status()))?;
        let addr = addr.as_ptr() as u64;
        unsafe {
            let dst = addr as *mut u8;
            core::ptr::copy_nonoverlapping(module.data.as_ptr(), dst, size);
        }
        module.set_physical_address(addr);
        next_base = Some(addr.saturating_add((pages * uefi::boot::PAGE_SIZE) as u64));
    }
    Ok(next_base.unwrap_or(0))
}

#[derive(Clone, Copy)]
struct ObjSection {
    sh_type: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    rel_addr: u64,
    loaded: bool,
}

const ET_REL: u16 = 1;
const EM_X86_64: u16 = 62;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_INIT_ARRAY: u32 = 14;
const SHT_FINI_ARRAY: u32 = 15;
const SHT_X86_64_UNWIND: u32 = 0x7000_0001;
const SHF_ALLOC: u64 = 0x2;

fn prepare_elf_obj_module(module: &mut Module) -> Result<()> {
    let image = &module.data;
    if image.len() < 64 || &image[0..4] != b"\x7fELF" {
        return Err(BootError::InvalidData("module is not ELF"));
    }
    if image[4] != 2 || image[5] != 1 || image[6] != 1 {
        return Err(BootError::InvalidData("unsupported module ELF format"));
    }
    if le_u16_at(image, 16)? != ET_REL || le_u16_at(image, 18)? != EM_X86_64 {
        return Err(BootError::InvalidData("module is not amd64 ET_REL"));
    }
    let shoff = usize::try_from(le_u64_at(image, 40)?)
        .map_err(|_| BootError::InvalidData("module section header offset overflow"))?;
    let shentsize = usize::from(le_u16_at(image, 58)?);
    let shnum = usize::from(le_u16_at(image, 60)?);
    let shstrndx = usize::from(le_u16_at(image, 62)?);
    if shnum == 0 || shentsize != 64 || shstrndx == 0 || shstrndx >= shnum {
        return Err(BootError::InvalidData("invalid module section headers"));
    }
    let shdr_len = shentsize
        .checked_mul(shnum)
        .ok_or(BootError::InvalidData("module section headers overflow"))?;
    let shdr_end = shoff
        .checked_add(shdr_len)
        .ok_or(BootError::InvalidData("module section headers overflow"))?;
    if shdr_end > image.len() {
        return Err(BootError::InvalidData(
            "module section headers out of range",
        ));
    }

    let mut sections = Vec::with_capacity(shnum);
    for index in 0..shnum {
        sections.push(read_obj_section(
            &image[shoff + index * shentsize..][..shentsize],
        )?);
    }

    let mut cursor = 0u64;
    for section in sections.iter_mut() {
        if section.size == 0 {
            continue;
        }
        if is_obj_program_section(section.sh_type) && (section.flags & SHF_ALLOC) != 0 {
            cursor = align_to(cursor, section.addralign)?;
            section.rel_addr = cursor;
            section.loaded = true;
            cursor = cursor
                .checked_add(section.size)
                .ok_or(BootError::InvalidData("module image size overflow"))?;
        }
    }

    let mut symtab_index = None;
    for (index, section) in sections.iter().enumerate() {
        if section.sh_type == SHT_SYMTAB {
            if symtab_index.is_some() {
                return Err(BootError::InvalidData("module has multiple symbol tables"));
            }
            symtab_index = Some(index);
        }
    }
    let symtab_index = symtab_index.ok_or(BootError::InvalidData("module has no symbol table"))?;
    cursor = align_to(cursor, sections[symtab_index].addralign)?;
    sections[symtab_index].rel_addr = cursor;
    sections[symtab_index].loaded = true;
    cursor = cursor
        .checked_add(sections[symtab_index].size)
        .ok_or(BootError::InvalidData("module image size overflow"))?;

    let symstr_index = sections[symtab_index].link as usize;
    if symstr_index >= shnum || sections[symstr_index].sh_type != SHT_STRTAB {
        return Err(BootError::InvalidData("module has invalid symbol strings"));
    }
    cursor = align_to(cursor, sections[symstr_index].addralign)?;
    sections[symstr_index].rel_addr = cursor;
    sections[symstr_index].loaded = true;
    cursor = cursor
        .checked_add(sections[symstr_index].size)
        .ok_or(BootError::InvalidData("module image size overflow"))?;

    if sections[shstrndx].sh_type != SHT_STRTAB {
        return Err(BootError::InvalidData("module has invalid section names"));
    }
    cursor = align_to(cursor, sections[shstrndx].addralign)?;
    sections[shstrndx].rel_addr = cursor;
    sections[shstrndx].loaded = true;
    cursor = cursor
        .checked_add(sections[shstrndx].size)
        .ok_or(BootError::InvalidData("module image size overflow"))?;

    for index in 0..sections.len() {
        let target = sections[index].info as usize;
        if (sections[index].sh_type == SHT_REL || sections[index].sh_type == SHT_RELA)
            && target < sections.len()
            && (sections[target].flags & SHF_ALLOC) != 0
        {
            cursor = align_to(cursor, sections[index].addralign)?;
            sections[index].rel_addr = cursor;
            sections[index].loaded = true;
            cursor = cursor
                .checked_add(sections[index].size)
                .ok_or(BootError::InvalidData("module image size overflow"))?;
        }
    }

    let mut loaded = vec![
        0u8;
        usize::try_from(cursor)
            .map_err(|_| BootError::InvalidData("module image too large"))?
    ];
    for section in sections.iter().filter(|section| section.loaded) {
        if section.sh_type == SHT_NOBITS {
            continue;
        }
        let src_start = usize::try_from(section.offset)
            .map_err(|_| BootError::InvalidData("module section offset overflow"))?;
        let size = usize::try_from(section.size)
            .map_err(|_| BootError::InvalidData("module section size overflow"))?;
        let src_end = src_start
            .checked_add(size)
            .ok_or(BootError::InvalidData("module section range overflow"))?;
        let dst_start = usize::try_from(section.rel_addr)
            .map_err(|_| BootError::InvalidData("module section address overflow"))?;
        let dst_end = dst_start
            .checked_add(size)
            .ok_or(BootError::InvalidData("module section range overflow"))?;
        if src_end > image.len() || dst_end > loaded.len() {
            return Err(BootError::InvalidData("module section out of range"));
        }
        loaded[dst_start..dst_end].copy_from_slice(&image[src_start..src_end]);
    }

    let mut elf_header = [0u8; 64];
    elf_header.copy_from_slice(&image[..64]);
    let mut shdr = image[shoff..shdr_end].to_vec();
    let mut section_addr_offsets = Vec::with_capacity(sections.len());
    for (index, section) in sections.iter().enumerate() {
        let addr_offset = if section.loaded {
            Some(section.rel_addr)
        } else {
            None
        };
        section_addr_offsets.push(addr_offset);
        shdr[index * shentsize + 16..index * shentsize + 24]
            .copy_from_slice(&section.rel_addr.to_le_bytes());
    }

    module.data = loaded;
    module.data_len = module.data.len();
    module.set_elf_metadata(elf_header, shdr, section_addr_offsets);
    Ok(())
}

fn relocated_elf_obj_section_headers(module: &Module, base: u64) -> Result<Vec<u8>> {
    let shentsize = 64usize;
    if module.section_headers.len() % shentsize != 0 {
        return Err(BootError::InvalidData("module section metadata is invalid"));
    }
    if module.section_addr_offsets.len() != module.section_headers.len() / shentsize {
        return Err(BootError::InvalidData(
            "module section address metadata is invalid",
        ));
    }
    let mut out = module.section_headers.clone();
    for (index, chunk) in out.chunks_mut(shentsize).enumerate() {
        if let Some(rel_addr) = module.section_addr_offsets[index] {
            let addr = base
                .checked_add(rel_addr)
                .ok_or(BootError::InvalidData("module section address overflow"))?;
            chunk[16..24].copy_from_slice(&addr.to_le_bytes());
        } else {
            chunk[16..24].copy_from_slice(&0u64.to_le_bytes());
        }
    }
    Ok(out)
}

fn read_obj_section(buf: &[u8]) -> Result<ObjSection> {
    Ok(ObjSection {
        sh_type: le_u32_at(buf, 4)?,
        flags: le_u64_at(buf, 8)?,
        offset: le_u64_at(buf, 24)?,
        size: le_u64_at(buf, 32)?,
        link: le_u32_at(buf, 40)?,
        info: le_u32_at(buf, 44)?,
        addralign: le_u64_at(buf, 48)?,
        rel_addr: 0,
        loaded: false,
    })
}

fn is_obj_program_section(sh_type: u32) -> bool {
    matches!(
        sh_type,
        SHT_PROGBITS | SHT_NOBITS | SHT_X86_64_UNWIND | SHT_INIT_ARRAY | SHT_FINI_ARRAY
    )
}

fn align_to(value: u64, align: u64) -> Result<u64> {
    let align = align.max(1);
    if !align.is_power_of_two() {
        return Err(BootError::InvalidData(
            "module section alignment is invalid",
        ));
    }
    let mask = align - 1;
    value
        .checked_add(mask)
        .map(|v| v & !mask)
        .ok_or(BootError::InvalidData("module section alignment overflow"))
}

fn page_align(value: u64) -> u64 {
    let mask = uefi::boot::PAGE_SIZE as u64 - 1;
    (value + mask) & !mask
}

fn le_u16_at(buf: &[u8], offset: usize) -> Result<u16> {
    let bytes = buf
        .get(offset..offset + 2)
        .ok_or(BootError::InvalidData("short little-endian u16"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32_at(buf: &[u8], offset: usize) -> Result<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(BootError::InvalidData("short little-endian u32"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_u64_at(buf: &[u8], offset: usize) -> Result<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(BootError::InvalidData("short little-endian u64"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
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

pub fn collect_efi_framebuffer_metadata() -> Result<Vec<u8>> {
    let handles = boot::locate_handle_buffer(SearchType::ByProtocol(&GraphicsOutput::GUID))
        .map_err(|err| BootError::Uefi(err.status()))?;
    let Some(handle) = handles.first().copied() else {
        return Err(BootError::InvalidData("GOP handle missing"));
    };
    let mut gop = unsafe {
        boot::open_protocol::<GraphicsOutput>(
            boot::OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            boot::OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|err| BootError::Uefi(err.status()))?
    };
    let info = gop.current_mode_info();
    let (width, height) = info.resolution();
    let stride = info.stride();
    let (red, green, blue, reserved) = match info.pixel_format() {
        PixelFormat::Rgb => (0x000000ff, 0x0000ff00, 0x00ff0000, 0xff000000),
        PixelFormat::Bgr => (0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000),
        PixelFormat::Bitmask => {
            let mask = info
                .pixel_bitmask()
                .ok_or(BootError::InvalidData("GOP bitmask missing"))?;
            (mask.red, mask.green, mask.blue, mask.reserved)
        }
        PixelFormat::BltOnly => {
            return Err(BootError::InvalidData("GOP framebuffer is blt-only"));
        }
    };
    let mut frame_buffer = gop.frame_buffer();
    let fb = EfiFramebuffer {
        fb_addr: frame_buffer.as_mut_ptr() as u64,
        fb_size: frame_buffer.size() as u64,
        fb_height: height as u32,
        fb_width: width as u32,
        fb_stride: stride as u32,
        fb_mask_red: red,
        fb_mask_green: green,
        fb_mask_blue: blue,
        fb_mask_reserved: reserved,
    };
    if fb.fb_addr == 0 || fb.fb_size == 0 || fb.fb_width == 0 || fb.fb_height == 0 {
        return Err(BootError::InvalidData("GOP framebuffer invalid"));
    }
    log::info!(
        "efi framebuffer: addr=0x{:x} size=0x{:x} {}x{} stride={} masks={:08x},{:08x},{:08x},{:08x}",
        fb.fb_addr,
        fb.fb_size,
        fb.fb_width,
        fb.fb_height,
        fb.fb_stride,
        fb.fb_mask_red,
        fb.fb_mask_green,
        fb.fb_mask_blue,
        fb.fb_mask_reserved
    );
    Ok(fb.to_bytes())
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
        if is_loader_private_env(&var.key) {
            continue;
        }
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

fn is_loader_private_env(key: &str) -> bool {
    key.starts_with("zfs_kunci_")
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

#[repr(C)]
struct EfiFramebuffer {
    fb_addr: u64,
    fb_size: u64,
    fb_height: u32,
    fb_width: u32,
    fb_stride: u32,
    fb_mask_red: u32,
    fb_mask_green: u32,
    fb_mask_blue: u32,
    fb_mask_reserved: u32,
}

impl EfiFramebuffer {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&self.fb_addr.to_le_bytes());
        bytes.extend_from_slice(&self.fb_size.to_le_bytes());
        bytes.extend_from_slice(&self.fb_height.to_le_bytes());
        bytes.extend_from_slice(&self.fb_width.to_le_bytes());
        bytes.extend_from_slice(&self.fb_stride.to_le_bytes());
        bytes.extend_from_slice(&self.fb_mask_red.to_le_bytes());
        bytes.extend_from_slice(&self.fb_mask_green.to_le_bytes());
        bytes.extend_from_slice(&self.fb_mask_blue.to_le_bytes());
        bytes.extend_from_slice(&self.fb_mask_reserved.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::string::ToString;

    use super::{build_efi_map_metadata_from_raw, build_envp, is_module_filename};
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
            conf_vars: alloc::vec![
                EnvVar {
                    key: "foo".to_string(),
                    value: "2".to_string(),
                },
                EnvVar {
                    key: "bar".to_string(),
                    value: "3".to_string(),
                }
            ],
        };
        let envp = build_envp(&env);
        let text = core::str::from_utf8(&envp).expect("utf8");
        assert!(text.contains("foo=1\0"));
        assert!(text.contains("bar=3\0"));
        assert!(text.ends_with("\0\0"));
        assert!(!text.contains("foo=2\0"));
    }

    #[test]
    fn test_build_envp_omits_loader_private_kunci_vars() {
        let env = LoaderEnv {
            env_vars: alloc::vec![
                EnvVar {
                    key: "zfs_kunci_http_driver".to_string(),
                    value: "\\EFI\\FreeBSD\\Drivers\\HttpDxe.efi".to_string(),
                },
                EnvVar {
                    key: "kern.zfs.key".to_string(),
                    value: "abcd".to_string(),
                },
                EnvVar {
                    key: "zfs_load".to_string(),
                    value: "YES".to_string(),
                },
            ],
            conf_vars: alloc::vec![],
        };

        let envp = build_envp(&env);
        let text = core::str::from_utf8(&envp).expect("utf8");
        assert!(!text.contains("zfs_kunci_http_driver="));
        assert!(text.contains("kern.zfs.key=abcd\0"));
        assert!(text.contains("zfs_load=YES\0"));
    }
}
