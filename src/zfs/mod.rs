extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::env::loader::LoaderEnv;
use crate::error::{BootError, Result};
use crate::kernel::module::Module;
use crate::kernel::types::ModuleType;
use crate::uefi_helpers::BlockDeviceInfo;
use crate::uefi_helpers::block_io::open_block_io;
use crate::uefi_helpers::device_path::{device_path_text_for_handle, partition_guid_for_handle};
use crate::zfs::fs::DatasetProps;
use crate::zfs::unlock::KeyLocation;

mod crypt;
pub mod fs;
mod label;
pub mod nvlist;
pub mod reader;
pub mod sha1;
pub mod sha256;
mod unlock;

pub use label::BootEnv;

const ZHAMEL_ZFSKEY_MODULE: &str = "zhamel_zfskey";
const ZHAMEL_ZFSKEY_PRELOAD_TYPE: &str = "zhamel_zfs_key";
const ZFS_MODULE: &str = "zfs";
const ZFS_ROOT_DEPENDENCY_MODULES: &[&str] = &["opensolaris", "xdr", "acl_nfs4", "crypto", "zlib"];
const ZHAMEL_ZFSKEY_MAGIC: &[u8; 8] = b"ZHMZKEY\0";
const ZHAMEL_ZFSKEY_VERSION: u32 = 1;
const ZHAMEL_ZFSKEY_WKEY_LEN: usize = 32;
const ZHAMEL_ZFSKEY_HEADER_LEN: usize = 40;

#[derive(Debug, Clone)]
pub struct ZfsPool {
    pub guid: u64,
    pub txg: u64,
    pub name: Option<String>,
    #[allow(dead_code)]
    pub ashift: Option<u64>,
    #[allow(dead_code)]
    pub handle: uefi::Handle,
    pub media_id: u32,
    pub block_size: usize,
    pub uber: Option<reader::types::Uberblock>,
    pub bootenv: Option<BootEnv>,
    pub bootenvs: Option<Vec<String>>,
}

pub fn probe_pools(devices: &[BlockDeviceInfo]) -> Vec<ZfsPool> {
    let mut pools = Vec::new();
    for (idx, device) in devices.iter().enumerate() {
        log_zfs_probe_candidate(idx, device);
        let block = match open_block_io(device.handle) {
            Ok(block) => block,
            Err(err) => {
                log::warn!(
                    "zfs: BlockIO open failed: {:?} idx={} handle={:p}",
                    err.status(),
                    idx,
                    device.handle.as_ptr()
                );
                continue;
            }
        };
        let labels = match label::probe_vdev_labels(
            &block,
            device.media_id,
            device.block_size as usize,
            device.last_block,
        ) {
            Ok(labels) => labels,
            Err(err) => {
                log::warn!(
                    "zfs: label probe failed: {} idx={} logical={} last_block={} block_size={}",
                    err,
                    idx,
                    device.logical_partition,
                    device.last_block,
                    device.block_size
                );
                continue;
            }
        };
        if labels.is_empty() {
            continue;
        }
        let mut best = labels[0].clone();
        for label in &labels[1..] {
            if label.pool_txg > best.pool_txg {
                best = label.clone();
            }
        }
        let uber = reader::read_best_uberblock(
            &block,
            device.media_id,
            device.block_size as usize,
            device.last_block,
            best.ashift,
        );
        let uber = match uber {
            Ok(uber) => uber,
            Err(err) => {
                log::warn!(
                    "zfs: uberblock probe failed: {} idx={} pool={} txg={}",
                    err,
                    idx,
                    best.pool_guid,
                    best.pool_txg
                );
                None
            }
        };
        let bootenvs = if let Some(uber) = uber.as_ref() {
            match reader::mos::list_bootenvs(
                &block,
                device.media_id,
                device.block_size as usize,
                uber,
            ) {
                Ok(list) => Some(list),
                Err(err) => {
                    log::warn!("zfs: bootenv list failed: {}", err);
                    None
                }
            }
        } else {
            None
        };
        let bootenv = match label::read_bootenv(
            &block,
            device.media_id,
            device.block_size as usize,
            device.last_block,
        ) {
            Ok(env) => env,
            Err(err) => {
                log::warn!("zfs: bootenv read failed: {}", err);
                None
            }
        };
        log::info!(
            "zfs: pool found idx={} guid={} txg={} name={:?} ashift={:?} uber={}",
            idx,
            best.pool_guid,
            best.pool_txg,
            best.pool_name,
            best.ashift,
            uber.is_some()
        );
        pools.push(ZfsPool {
            guid: best.pool_guid,
            txg: best.pool_txg,
            name: best.pool_name.clone(),
            ashift: best.ashift,
            handle: device.handle,
            media_id: device.media_id,
            block_size: device.block_size as usize,
            uber,
            bootenv,
            bootenvs,
        });
    }
    pools
}

fn log_zfs_probe_candidate(idx: usize, device: &BlockDeviceInfo) {
    let guid = partition_guid_for_handle(device.handle)
        .map(format_guid)
        .unwrap_or_else(|| "<none>".to_string());
    let path =
        device_path_text_for_handle(device.handle).unwrap_or_else(|| "<unavailable>".to_string());
    log::info!(
        "zfs: probe candidate idx={} handle={:p} logical={} media_id={} block_size={} last_block={} removable={} readonly={} guid={} path={}",
        idx,
        device.handle.as_ptr(),
        device.logical_partition,
        device.media_id,
        device.block_size,
        device.last_block,
        device.removable,
        device.read_only,
        guid,
        path
    );
}

fn format_guid(guid: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid[3],
        guid[2],
        guid[1],
        guid[0],
        guid[5],
        guid[4],
        guid[7],
        guid[6],
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
}

pub fn log_bootenv(pools: &[ZfsPool]) {
    for pool in pools {
        let txg = pool.txg;
        if let Some(env) = &pool.bootenv {
            if let Some(bootonce) = &env.bootonce {
                log::info!(
                    "zfs: pool {} txg={} bootenv v{} bootonce={}",
                    pool.guid,
                    txg,
                    env.version,
                    bootonce
                );
            } else if let Some(raw) = &env.raw_envmap {
                log::info!(
                    "zfs: pool {} txg={} bootenv v{} raw={}",
                    pool.guid,
                    txg,
                    env.version,
                    raw
                );
            } else {
                log::info!(
                    "zfs: pool {} txg={} bootenv v{} empty",
                    pool.guid,
                    txg,
                    env.version
                );
            }
        } else {
            log::info!("zfs: pool {} txg={} bootenv missing", pool.guid, txg);
        }
    }
}

pub fn bootonce_for_pools(pools: &[ZfsPool]) -> Option<&str> {
    for pool in pools {
        if let Some(env) = &pool.bootenv {
            if let Some(bootonce) = env.bootonce.as_deref() {
                return Some(bootonce);
            }
        }
    }
    None
}

pub fn find_pool_for_bootenv<'a>(
    pools: &'a [ZfsPool],
    bootenv: &str,
) -> Option<(&'a ZfsPool, String)> {
    let mut normalized = bootenv.trim();
    if let Some(stripped) = normalized.strip_prefix("zfs:") {
        normalized = stripped;
    }
    normalized = normalized.trim_end_matches(':');
    let mut parts = normalized.splitn(2, '/');
    let first = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("");
    if !rest.is_empty() {
        if let Some(pool) = pools
            .iter()
            .find(|pool| pool.name.as_deref() == Some(first))
        {
            return Some((pool, rest.to_string()));
        }
    }
    if pools.len() == 1 {
        return Some((pools.first().unwrap(), normalized.to_string()));
    }
    None
}

pub fn export_env(loader_env: &mut LoaderEnv, pools: &[ZfsPool]) {
    loader_env.set("zfs_pools", &pools.len().to_string());
    if pools.len() == 1 {
        loader_env.set_if_unset("zfs_pool_guid", &pools[0].guid.to_string());
        loader_env.set_if_unset("zfs_pool_txg", &pools[0].txg.to_string());
        if let Some(name) = pools[0].name.as_deref() {
            loader_env.set_if_unset("zfs_pool_name", name);
        }
    }
    if let Some(bootonce) = bootonce_for_pools(pools) {
        loader_env.set_if_unset("zfs_bootonce", bootonce);
        apply_bootonce_selection(loader_env, bootonce);
    }
    if let Some(pools) = pools.first() {
        if let Some(list) = pools.bootenvs.as_ref() {
            export_bootenv_list(loader_env, pools, list);
        }
    }
}

fn apply_bootonce_selection(loader_env: &mut LoaderEnv, bootonce: &str) {
    let active = format!("zfs:{}:", bootonce);
    loader_env.set_if_unset("zfs_be_active", &active);
    loader_env.set_if_unset("zfs_be_currpage", "1");

    let (root, be_name) = split_bootenv(bootonce);
    loader_env.set_if_unset("zfs_be_root", root);

    let entry = format!("zfs:{}/{}", root, be_name);
    loader_env.set_if_unset("bootenvs[0]", &entry);
    loader_env.set_if_unset("bootenvs_count", "1");
    loader_env.set_if_unset("bootenvmenu_caption[4]", be_name);
    let cmd = format!("set currdev={}", active);
    loader_env.set_if_unset("bootenvmenu_command[4]", &cmd);
}

fn export_bootenv_list(loader_env: &mut LoaderEnv, pool: &ZfsPool, entries: &[String]) {
    if entries.is_empty() {
        return;
    }
    let root = if let Some(bootonce) = pool
        .bootenv
        .as_ref()
        .and_then(|env| env.bootonce.as_deref())
    {
        split_bootenv(bootonce).0
    } else if let Some(name) = pool.name.as_deref() {
        name
    } else {
        return;
    };
    for (idx, entry) in entries.iter().enumerate() {
        let env_name = format!("bootenvs[{}]", idx);
        let env_val = format!("zfs:{}/{}", root, entry);
        loader_env.set_if_unset(&env_name, &env_val);
    }
    loader_env.set_if_unset("bootenvs_count", &entries.len().to_string());
    log::info!("zfs bootenvs: {}", entries.len());
}

fn split_bootenv(bootonce: &str) -> (&str, &str) {
    match bootonce.rsplit_once('/') {
        Some((root, name)) if !root.is_empty() && !name.is_empty() => (root, name),
        _ => (bootonce, bootonce),
    }
}

pub fn validate_bootenv(pools: &[ZfsPool]) -> Result<()> {
    for pool in pools {
        if let Some(env) = &pool.bootenv {
            if env.version > 1 {
                return Err(BootError::InvalidData("bootenv version unsupported"));
            }
        }
    }
    Ok(())
}

pub fn maybe_unlock_kunci(pools: &[ZfsPool], env: &mut LoaderEnv) -> Result<()> {
    let Some(target) = unlock_dataset_target(env) else {
        return Ok(());
    };
    let Some((pool, dataset_path)) = find_pool_for_bootenv(pools, &target) else {
        log::warn!("zfs: unlock target not found: {}", target);
        return Ok(());
    };
    let block = open_block_io(pool.handle).map_err(|err| BootError::Uefi(err.status()))?;
    let uber = pool
        .uber
        .ok_or(BootError::InvalidData("uberblock missing"))?;
    let props = match fs::bootenv_dataset_props(
        &block,
        pool.media_id,
        pool.block_size,
        uber,
        &dataset_path,
    ) {
        Ok(props) => props,
        Err(err) => {
            log::warn!("zfs: dataset props lookup failed: {}", err);
            return Ok(());
        }
    };
    log::info!(
        "zfs: dataset props keyformat={:?} keylocation={:?} kunci_jwe={} pbkdf2_salt={} pbkdf2_iters={:?}",
        props.keyformat,
        props.keylocation,
        props.kunci_jwe.is_some(),
        props.pbkdf2_salt.is_some(),
        props.pbkdf2_iters
    );
    if props.kunci_jwe.is_none() {
        return Ok(());
    }
    unlock::maybe_unlock_kunci(env, &props)
}

pub fn maybe_prompt_passphrase(pools: &[ZfsPool], env: &mut LoaderEnv) -> Result<()> {
    let Some(target) = unlock_dataset_target(env) else {
        return Ok(());
    };
    if let Some(keyformat) = env.get("zfs_keyformat") {
        let keylocation = env.get("zfs_keylocation").map(|val| val.to_string());
        let pbkdf2_salt = env.get("zfs_pbkdf2salt").and_then(parse_u64_env);
        let pbkdf2_iters = env.get("zfs_pbkdf2iters").and_then(parse_u64_env);
        let props = DatasetProps {
            keyformat: Some(keyformat.to_string()),
            keylocation,
            kunci_jwe: None,
            pbkdf2_salt,
            pbkdf2_iters,
            crypto_key: None,
        };
        log::info!("zfs: using keyformat/keylocation override from env");
        if !needs_passphrase(&props) {
            return Ok(());
        }
        if props.pbkdf2_salt.is_none() || props.pbkdf2_iters.is_none() {
            log::warn!(
                "zfs: passphrase override missing pbkdf2salt/pbkdf2iters; using dataset props"
            );
        } else {
            let Some((pool, dataset_path)) = find_pool_for_bootenv(pools, &target) else {
                log::warn!("zfs: unlock target not found: {}", target);
                return Ok(());
            };
            let block = open_block_io(pool.handle).map_err(|err| BootError::Uefi(err.status()))?;
            let uber = pool
                .uber
                .ok_or(BootError::InvalidData("uberblock missing"))?;
            let dataset_props = fs::bootenv_dataset_props(
                &block,
                pool.media_id,
                pool.block_size,
                uber,
                &dataset_path,
            )?;
            let props = DatasetProps {
                crypto_key: dataset_props.crypto_key,
                ..props
            };
            let bootfs_objset = fs::bootfs_objset(&block, pool.media_id, pool.block_size, uber)?;
            return unlock::maybe_prompt_passphrase(
                env,
                &props,
                &block,
                pool.media_id,
                pool.block_size,
                &bootfs_objset,
            );
        }
    }
    let Some((pool, dataset_path)) = find_pool_for_bootenv(pools, &target) else {
        log::warn!("zfs: unlock target not found: {}", target);
        return Ok(());
    };
    let block = open_block_io(pool.handle).map_err(|err| BootError::Uefi(err.status()))?;
    let uber = pool
        .uber
        .ok_or(BootError::InvalidData("uberblock missing"))?;
    let props = match fs::bootenv_dataset_props(
        &block,
        pool.media_id,
        pool.block_size,
        uber,
        &dataset_path,
    ) {
        Ok(props) => props,
        Err(err) => {
            log::warn!("zfs: dataset props lookup failed: {}", err);
            return Ok(());
        }
    };
    log::info!(
        "zfs: dataset props keyformat={:?} keylocation={:?} pbkdf2_salt={} pbkdf2_iters={:?}",
        props.keyformat,
        props.keylocation,
        props.pbkdf2_salt.is_some(),
        props.pbkdf2_iters
    );
    if !needs_passphrase(&props) {
        return Ok(());
    }
    log::info!("zfs: passphrase required for {}", dataset_path);
    let bootfs_objset = fs::bootfs_objset(&block, pool.media_id, pool.block_size, uber)?;
    unlock::maybe_prompt_passphrase(
        env,
        &props,
        &block,
        pool.media_id,
        pool.block_size,
        &bootfs_objset,
    )
}

pub fn maybe_prepare_zfskey_handoff(
    pools: &[ZfsPool],
    env: &mut LoaderEnv,
) -> Result<Option<Module>> {
    let Some(target) = unlock_dataset_target(env) else {
        return Ok(None);
    };
    enable_zfs_root_module(env);
    let Some((pool, dataset_path)) = find_pool_for_bootenv(pools, &target) else {
        log::warn!("zfs: zfskey handoff target not found: {}", target);
        return Ok(None);
    };
    let block = open_block_io(pool.handle).map_err(|err| BootError::Uefi(err.status()))?;
    let uber = pool
        .uber
        .ok_or(BootError::InvalidData("uberblock missing"))?;
    let props = match fs::bootenv_dataset_props(
        &block,
        pool.media_id,
        pool.block_size,
        uber,
        &dataset_path,
    ) {
        Ok(props) => props,
        Err(err) => {
            log::warn!("zfs: zfskey dataset props lookup failed: {}", err);
            return Ok(None);
        }
    };

    let key = match zfskey_handoff_key(env, &props, &block, pool, uber)? {
        Some(key) => key,
        None => return Ok(None),
    };
    let payload = build_zfskey_handoff_payload(&target, &key)?;
    enable_zfskey_helper_module(env);
    core::mem::forget(block);
    log::info!("zfs: native key handoff BlockIO retained");
    log::info!(
        "zfs: prepared native key handoff for {} (payload_len={})",
        target,
        payload.len()
    );
    let module = Module::new(
        ZHAMEL_ZFSKEY_PRELOAD_TYPE.to_string(),
        ModuleType::Raw(ZHAMEL_ZFSKEY_PRELOAD_TYPE.to_string()),
        payload,
    );
    log::info!("zfs: native key handoff module object created");
    Ok(Some(module))
}

fn enable_zfs_root_module(env: &mut LoaderEnv) {
    for module in ZFS_ROOT_DEPENDENCY_MODULES {
        enable_optional_kld_module(env, module);
    }
    env.set_if_unset("zfs_load", "YES");
    env.set_if_unset("zfs_name", ZFS_MODULE);
    env.set_if_unset("zfs_type", "kld");
    log::info!(
        "zfs: enabled zfs root module load={:?} name={:?} type={:?}",
        env.get("zfs_load"),
        env.get("zfs_name"),
        env.get("zfs_type")
    );
}

fn enable_optional_kld_module(env: &mut LoaderEnv, module: &str) {
    env.set_if_unset(&format!("{}_load", module), "YES");
    env.set_if_unset(&format!("{}_name", module), module);
    env.set_if_unset(&format!("{}_type", module), "kld");
    env.set_if_unset(
        &format!("{}_loaderror", module),
        &format!("echo zfs: optional dependency {}.ko not found", module),
    );
}

fn zfskey_handoff_key(
    env: &mut LoaderEnv,
    props: &DatasetProps,
    block: &uefi::proto::media::block::BlockIO,
    pool: &ZfsPool,
    uber: reader::types::Uberblock,
) -> Result<Option<Vec<u8>>> {
    if let Some(mut hex) = env.take("kern.zfs.key") {
        let key = unlock::hex_decode(&hex)?;
        unlock::scrub_string(&mut hex);
        validate_zfskey_len(&key)?;
        log::info!("zfs: using prepared native key from env");
        return Ok(Some(key));
    }

    if let Some(jwe) = props.kunci_jwe.as_deref() {
        log::info!("zfs: decrypting kunci key for native handoff");
        let url_override = env.get("zfs_kunci_url");
        let http_driver = env.get("zfs_kunci_http_driver");
        let local_ip = env.get("zfs_kunci_ip").and_then(parse_ipv4_env);
        let netmask = env.get("zfs_kunci_netmask").and_then(parse_ipv4_env);
        let key = crate::tang::decrypt_tang_jwe(jwe, url_override, http_driver, local_ip, netmask)?;
        validate_zfskey_len(&key)?;
        return Ok(Some(key));
    }

    if !matches!(
        props.keyformat.as_deref(),
        Some(format) if format.eq_ignore_ascii_case("raw")
    ) {
        return Ok(None);
    }

    let Some(keylocation) = props.keylocation.as_deref() else {
        log::warn!("zfs: raw keyformat has no keylocation for native handoff");
        return Ok(None);
    };
    let KeyLocation::File(path) = unlock::parse_keylocation(keylocation) else {
        log::warn!("zfs: raw keylocation unsupported for native handoff");
        return Ok(None);
    };
    match read_raw_keylocation_file(block, pool, uber, &path) {
        Ok(key) => {
            validate_zfskey_len(&key)?;
            Ok(Some(key))
        }
        Err(err) => {
            log::warn!("zfs: raw keylocation file read failed for handoff: {}", err);
            Ok(None)
        }
    }
}

fn read_raw_keylocation_file(
    block: &uefi::proto::media::block::BlockIO,
    pool: &ZfsPool,
    uber: reader::types::Uberblock,
    path: &str,
) -> Result<Vec<u8>> {
    match fs::datasets_for_mountpoint(pool, "/boot") {
        Ok(datasets) => {
            for dataset in datasets {
                for dataset_path in paths_for_boot_dataset(path) {
                    match fs::read_file_from_bootenv(pool, &dataset, &dataset_path) {
                        Ok(bytes) => {
                            log::info!(
                                "zfs: raw keylocation read from /boot dataset {} path {}",
                                dataset,
                                dataset_path
                            );
                            return Ok(bytes);
                        }
                        Err(err) => {
                            log::warn!(
                                "zfs: raw keylocation /boot dataset read failed: dataset={} path={} err={}",
                                dataset,
                                dataset_path,
                                err
                            );
                        }
                    }
                }
            }
        }
        Err(err) => {
            log::warn!("zfs: raw keylocation /boot dataset lookup failed: {}", err);
        }
    }

    let bootfs_objset = fs::bootfs_objset(block, pool.media_id, pool.block_size, uber)?;
    for bootfs_path in paths_for_boot_dataset(path) {
        match fs::read_file_from_objset(
            block,
            pool.media_id,
            pool.block_size,
            &bootfs_objset,
            &bootfs_path,
        ) {
            Ok(bytes) => {
                log::info!("zfs: raw keylocation read from bootfs path {}", bootfs_path);
                return Ok(bytes);
            }
            Err(err) => {
                log::warn!(
                    "zfs: raw keylocation bootfs read failed: path={} err={}",
                    bootfs_path,
                    err
                );
            }
        }
    }
    Err(BootError::InvalidData("zfs raw keylocation file missing"))
}

fn paths_for_boot_dataset(path: &str) -> Vec<String> {
    let primary = path_for_boot_dataset(path);
    let fallback = normalize_zfs_path(path);
    if primary == fallback {
        let mut out = Vec::new();
        out.push(primary);
        out
    } else {
        let mut out = Vec::new();
        out.push(primary);
        out.push(fallback);
        out
    }
}

fn path_for_boot_dataset(path: &str) -> String {
    let normalized = normalize_zfs_path(path);
    if normalized == "/boot" {
        return "/".to_string();
    }
    if let Some(stripped) = normalized.strip_prefix("/boot/") {
        return format!("/{}", stripped);
    }
    normalized
}

fn normalize_zfs_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    }
}

fn validate_zfskey_len(key: &[u8]) -> Result<()> {
    if key.len() == ZHAMEL_ZFSKEY_WKEY_LEN {
        Ok(())
    } else {
        Err(BootError::InvalidData(
            "zfs raw key must be exactly 32 bytes",
        ))
    }
}

fn build_zfskey_handoff_payload(dataset: &str, key: &[u8]) -> Result<Vec<u8>> {
    validate_zfskey_len(key)?;
    if dataset.as_bytes().contains(&0) {
        return Err(BootError::InvalidData("zfs dataset contains nul byte"));
    }
    let dataset_len = dataset.len() + 1;
    let mut payload = Vec::with_capacity(ZHAMEL_ZFSKEY_HEADER_LEN + dataset_len + key.len());
    payload.extend_from_slice(ZHAMEL_ZFSKEY_MAGIC);
    payload.extend_from_slice(&ZHAMEL_ZFSKEY_VERSION.to_le_bytes());
    payload.extend_from_slice(&(ZHAMEL_ZFSKEY_HEADER_LEN as u32).to_le_bytes());
    payload.extend_from_slice(&(dataset_len as u32).to_le_bytes());
    payload.extend_from_slice(&(key.len() as u32).to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&[0u8; 12]);
    payload.extend_from_slice(dataset.as_bytes());
    payload.push(0);
    payload.extend_from_slice(key);
    Ok(payload)
}

fn enable_zfskey_helper_module(env: &mut LoaderEnv) {
    env.set_if_unset("zhamel_zfskey_load", "YES");
    env.set_if_unset("zhamel_zfskey_name", ZHAMEL_ZFSKEY_MODULE);
    env.set_if_unset("zhamel_zfskey_type", "kld");
    append_module_path(env, "/boot/modules");
    log::info!(
        "zfs: enabled zfskey helper load={:?} name={:?} type={:?} module_path={:?}",
        env.get("zhamel_zfskey_load"),
        env.get("zhamel_zfskey_name"),
        env.get("zhamel_zfskey_type"),
        env.get("module_path")
    );
}

fn append_module_path(env: &mut LoaderEnv, entry: &str) {
    let current = env.get("module_path").unwrap_or("/boot/kernel").to_string();
    if module_path_contains(&current, entry) {
        return;
    }
    let updated = if current.trim().is_empty() {
        entry.to_string()
    } else {
        format!("{};{}", current, entry)
    };
    env.set("module_path", &updated);
}

fn module_path_contains(path_list: &str, entry: &str) -> bool {
    let target = entry.trim_end_matches('/');
    path_list
        .split(';')
        .map(str::trim)
        .any(|path| path.trim_end_matches('/') == target)
}

fn parse_ipv4_env(value: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut idx = 0usize;
    for part in value.split('.') {
        if idx >= out.len() {
            return None;
        }
        out[idx] = part.trim().parse::<u8>().ok()?;
        idx += 1;
    }
    if idx == out.len() { Some(out) } else { None }
}

fn parse_u64_env(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

fn unlock_dataset_target(env: &LoaderEnv) -> Option<String> {
    if let Some(root) = env
        .get("vfs.root.mountfrom")
        .and_then(root_dataset_from_mountfrom)
    {
        log::info!("zfs: unlock target from vfs.root.mountfrom: {}", root);
        return Some(root);
    }
    env.get("zfs_be_active")
        .or_else(|| env.get("zfs_bootonce"))
        .map(ToString::to_string)
}

fn root_dataset_from_mountfrom(value: &str) -> Option<String> {
    let rest = value.trim().strip_prefix("zfs:")?;
    let dataset = rest
        .split_ascii_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches(':');
    if dataset.is_empty() {
        None
    } else {
        Some(dataset.to_string())
    }
}

fn needs_passphrase(props: &DatasetProps) -> bool {
    matches!(
        props.keyformat.as_deref(),
        Some(format) if format.eq_ignore_ascii_case("passphrase")
    )
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::ptr::NonNull;

    use crate::env::loader::LoaderEnv;
    use crate::env::parser::EnvVar;
    use crate::zfs::{
        BootEnv, ZfsPool, apply_bootonce_selection, export_bootenv_list,
        root_dataset_from_mountfrom, split_bootenv, unlock_dataset_target,
    };

    use super::{
        ZHAMEL_ZFSKEY_HEADER_LEN, ZHAMEL_ZFSKEY_MAGIC, build_zfskey_handoff_payload, export_env,
        find_pool_for_bootenv, paths_for_boot_dataset,
    };

    #[test]
    fn export_env_single_pool() {
        let mut env = LoaderEnv {
            env_vars: Vec::new(),
            conf_vars: Vec::new(),
        };
        let pools = vec![ZfsPool {
            guid: 42,
            txg: 7,
            name: None,
            ashift: None,
            handle: unsafe { uefi::Handle::new(NonNull::dangling()) },
            media_id: 0,
            block_size: 512,
            uber: None,
            bootenv: Some(BootEnv {
                version: 1,
                bootonce: Some("zroot/ROOT/default".to_string()),
                raw_envmap: None,
            }),
            bootenvs: None,
        }];
        export_env(&mut env, &pools);
        assert_eq!(env.get("zfs_pools"), Some("1"));
        assert_eq!(env.get("zfs_pool_guid"), Some("42"));
        assert_eq!(env.get("zfs_pool_txg"), Some("7"));
        assert_eq!(env.get("zfs_bootonce"), Some("zroot/ROOT/default"));
        assert_eq!(env.get("zfs_be_root"), Some("zroot/ROOT"));
        assert_eq!(env.get("bootenvs_count"), Some("1"));
        assert_eq!(env.get("bootenvs[0]"), Some("zfs:zroot/ROOT/default"));
    }

    #[test]
    fn export_env_multiple_pools() {
        let mut env = LoaderEnv {
            env_vars: vec![EnvVar {
                key: "zfs_pool_guid".to_string(),
                value: "999".to_string(),
            }],
            conf_vars: Vec::new(),
        };
        let pools = vec![
            ZfsPool {
                guid: 1,
                txg: 1,
                name: None,
                ashift: None,
                handle: unsafe { uefi::Handle::new(NonNull::dangling()) },
                media_id: 0,
                block_size: 512,
                uber: None,
                bootenv: None,
                bootenvs: None,
            },
            ZfsPool {
                guid: 2,
                txg: 2,
                name: None,
                ashift: None,
                handle: unsafe { uefi::Handle::new(NonNull::dangling()) },
                media_id: 0,
                block_size: 512,
                uber: None,
                bootenv: None,
                bootenvs: None,
            },
        ];
        export_env(&mut env, &pools);
        assert_eq!(env.get("zfs_pools"), Some("2"));
        assert_eq!(env.get("zfs_pool_guid"), Some("999"));
        assert!(env.get("zfs_pool_txg").is_none());
    }

    #[test]
    fn split_bootenv_basic() {
        let (root, name) = split_bootenv("zroot/ROOT/default");
        assert_eq!(root, "zroot/ROOT");
        assert_eq!(name, "default");
    }

    #[test]
    fn apply_bootonce_sets_menu() {
        let mut env = LoaderEnv {
            env_vars: Vec::new(),
            conf_vars: Vec::new(),
        };
        apply_bootonce_selection(&mut env, "zroot/ROOT/default");
        assert_eq!(env.get("zfs_be_active"), Some("zfs:zroot/ROOT/default:"));
        assert_eq!(env.get("bootenvmenu_caption[4]"), Some("default"));
        assert_eq!(
            env.get("bootenvmenu_command[4]"),
            Some("set currdev=zfs:zroot/ROOT/default:")
        );
    }

    #[test]
    fn export_bootenv_list_sets_entries() {
        let mut env = LoaderEnv {
            env_vars: Vec::new(),
            conf_vars: Vec::new(),
        };
        let pool = ZfsPool {
            guid: 1,
            txg: 1,
            name: Some("zroot/ROOT".to_string()),
            ashift: None,
            handle: unsafe { uefi::Handle::new(NonNull::dangling()) },
            media_id: 0,
            block_size: 512,
            uber: None,
            bootenv: None,
            bootenvs: Some(vec!["default".to_string(), "alt".to_string()]),
        };
        export_bootenv_list(&mut env, &pool, pool.bootenvs.as_ref().unwrap());
        assert_eq!(env.get("bootenvs_count"), Some("2"));
        assert_eq!(env.get("bootenvs[0]"), Some("zfs:zroot/ROOT/default"));
        assert_eq!(env.get("bootenvs[1]"), Some("zfs:zroot/ROOT/alt"));
    }

    #[test]
    fn find_pool_for_bootenv_matches_named_pool() {
        let pools = vec![ZfsPool {
            guid: 1,
            txg: 1,
            name: Some("zroot".to_string()),
            ashift: None,
            handle: unsafe { uefi::Handle::new(NonNull::dangling()) },
            media_id: 0,
            block_size: 512,
            uber: None,
            bootenv: None,
            bootenvs: None,
        }];
        let (pool, dataset) = find_pool_for_bootenv(&pools, "zroot/ROOT/default").expect("pool");
        assert_eq!(pool.guid, 1);
        assert_eq!(dataset, "ROOT/default");
    }

    #[test]
    fn find_pool_for_bootenv_single_pool_fallback() {
        let pools = vec![ZfsPool {
            guid: 2,
            txg: 2,
            name: None,
            ashift: None,
            handle: unsafe { uefi::Handle::new(NonNull::dangling()) },
            media_id: 0,
            block_size: 512,
            uber: None,
            bootenv: None,
            bootenvs: None,
        }];
        let (pool, dataset) = find_pool_for_bootenv(&pools, "ROOT/default").expect("pool");
        assert_eq!(pool.guid, 2);
        assert_eq!(dataset, "ROOT/default");
    }

    #[test]
    fn root_dataset_from_mountfrom_parses_zfs_root() {
        assert_eq!(
            root_dataset_from_mountfrom("zfs:zroot-waka/zung/system"),
            Some("zroot-waka/zung/system".to_string())
        );
        assert_eq!(
            root_dataset_from_mountfrom("zfs:zroot/ROOT/default ro"),
            Some("zroot/ROOT/default".to_string())
        );
        assert_eq!(root_dataset_from_mountfrom("ufs:/dev/ada0p2"), None);
    }

    #[test]
    fn unlock_dataset_target_prefers_root_mountfrom() {
        let mut env = LoaderEnv {
            env_vars: Vec::new(),
            conf_vars: Vec::new(),
        };
        env.set("zfs_be_active", "zfs:zroot/ROOT/default:");
        env.set("vfs.root.mountfrom", "zfs:zroot-waka/zung/system");

        assert_eq!(
            unlock_dataset_target(&env),
            Some("zroot-waka/zung/system".to_string())
        );
    }

    #[test]
    fn zfskey_payload_matches_kernel_module_header() {
        let key = [0x5au8; 32];
        let payload = build_zfskey_handoff_payload("zroot/ROOT/default", &key).expect("payload");

        assert_eq!(&payload[0..8], ZHAMEL_ZFSKEY_MAGIC);
        assert_eq!(u32::from_le_bytes(payload[8..12].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(payload[12..16].try_into().unwrap()),
            ZHAMEL_ZFSKEY_HEADER_LEN as u32
        );
        assert_eq!(u32::from_le_bytes(payload[16..20].try_into().unwrap()), 19);
        assert_eq!(u32::from_le_bytes(payload[20..24].try_into().unwrap()), 32);
        assert_eq!(u32::from_le_bytes(payload[24..28].try_into().unwrap()), 0);
        assert_eq!(&payload[28..40], &[0u8; 12]);
        assert_eq!(&payload[40..59], b"zroot/ROOT/default\0");
        assert_eq!(&payload[59..91], &key);
    }

    #[test]
    fn zfskey_payload_rejects_non_raw_key_length() {
        assert!(build_zfskey_handoff_payload("zroot/ROOT/default", &[1, 2, 3]).is_err());
    }

    #[test]
    fn raw_keylocation_paths_try_boot_relative_first() {
        assert_eq!(
            paths_for_boot_dataset("/boot/keys/root.key"),
            vec![
                "/keys/root.key".to_string(),
                "/boot/keys/root.key".to_string()
            ]
        );
        assert_eq!(
            paths_for_boot_dataset("/keys/root.key"),
            vec!["/keys/root.key".to_string()]
        );
    }
}
