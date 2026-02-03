extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::boot;
use uefi::proto::media::block::BlockIO;

use crate::env::loader::LoaderEnv;
use crate::error::{BootError, Result};
use crate::uefi_helpers::BlockDeviceInfo;
use crate::zfs::fs::DatasetProps;

mod label;
pub mod sha256;
pub mod nvlist;
pub mod reader;
pub mod fs;
mod unlock;

pub use label::BootEnv;

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
    for device in devices {
        let block = match boot::open_protocol_exclusive::<BlockIO>(device.handle) {
            Ok(block) => block,
            Err(err) => {
                log::warn!("zfs: BlockIO open failed: {:?}", err.status());
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
                log::warn!("zfs: label probe failed: {}", err);
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
        )
        .ok()
        .flatten();
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
            log::info!(
                "zfs: pool {} txg={} bootenv missing",
                pool.guid,
                txg
            );
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
        if let Some(pool) = pools.iter().find(|pool| pool.name.as_deref() == Some(first)) {
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
    let bootenv = env
        .get("zfs_be_active")
        .or_else(|| env.get("zfs_bootonce"));
    let Some(bootenv) = bootenv else {
        return Ok(());
    };
    let Some((pool, bootenv_path)) = find_pool_for_bootenv(pools, bootenv) else {
        return Ok(());
    };
    let block = boot::open_protocol_exclusive::<BlockIO>(pool.handle)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let uber = pool
        .uber
        .ok_or(BootError::InvalidData("uberblock missing"))?;
    let props = match fs::bootenv_dataset_props(
        &block,
        pool.media_id,
        pool.block_size,
        uber,
        &bootenv_path,
    ) {
        Ok(props) => props,
        Err(err) => {
            log::warn!("zfs: dataset props lookup failed: {}", err);
            return Ok(());
        }
    };
    if props.kunci_jwe.is_none() {
        return Ok(());
    }
    unlock::maybe_unlock_kunci(env, &props)
}

pub fn maybe_prompt_passphrase(pools: &[ZfsPool], env: &mut LoaderEnv) -> Result<()> {
    let bootenv = env
        .get("zfs_be_active")
        .or_else(|| env.get("zfs_bootonce"));
    let Some(bootenv) = bootenv else {
        return Ok(());
    };
    if let Some(keyformat) = env.get("zfs_keyformat") {
        let keylocation = env.get("zfs_keylocation").map(|val| val.to_string());
        let props = DatasetProps {
            keyformat: Some(keyformat.to_string()),
            keylocation,
            kunci_jwe: None,
        };
        log::info!("zfs: using keyformat/keylocation override from env");
        if !needs_passphrase(&props) {
            return Ok(());
        }
        let Some((pool, _)) = find_pool_for_bootenv(pools, bootenv) else {
            return Ok(());
        };
        let block = boot::open_protocol_exclusive::<BlockIO>(pool.handle)
            .map_err(|err| BootError::Uefi(err.status()))?;
        let uber = pool
            .uber
            .ok_or(BootError::InvalidData("uberblock missing"))?;
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
    let Some((pool, bootenv_path)) = find_pool_for_bootenv(pools, bootenv) else {
        return Ok(());
    };
    let block = boot::open_protocol_exclusive::<BlockIO>(pool.handle)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let uber = pool
        .uber
        .ok_or(BootError::InvalidData("uberblock missing"))?;
    let props = match fs::bootenv_dataset_props(
        &block,
        pool.media_id,
        pool.block_size,
        uber,
        &bootenv_path,
    ) {
        Ok(props) => props,
        Err(err) => {
            log::warn!("zfs: dataset props lookup failed: {}", err);
            return Ok(());
        }
    };
    log::info!(
        "zfs: dataset props keyformat={:?} keylocation={:?}",
        props.keyformat,
        props.keylocation
    );
    if !needs_passphrase(&props) {
        return Ok(());
    }
    log::info!("zfs: passphrase required for {}", bootenv_path);
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
    use crate::zfs::{apply_bootonce_selection, export_bootenv_list, split_bootenv, BootEnv, ZfsPool};

    use super::{export_env, find_pool_for_bootenv};

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
}
