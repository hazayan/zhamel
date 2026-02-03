use crate::env::loader::LoaderEnv;

#[allow(dead_code)]
pub struct BlockCacheConfig {
    pub capacity_bytes: usize,
}

pub fn init(loader_env: &LoaderEnv) -> BlockCacheConfig {
    let capacity = loader_env
        .get("zhamel_block_cache_bytes")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(8 * 1024 * 1024);
    log::info!("block cache: {} bytes", capacity);
    BlockCacheConfig {
        capacity_bytes: capacity,
    }
}
