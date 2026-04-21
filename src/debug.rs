use core::sync::atomic::{AtomicBool, Ordering};

use crate::env::loader::LoaderEnv;

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn init(env: &LoaderEnv) {
    let enabled = env
        .get("zhamel_debug")
        .or_else(|| env.get("boot_verbose"))
        .map(is_truthy)
        .unwrap_or(false);
    DEBUG_ENABLED.store(enabled, Ordering::Relaxed);
    log::set_max_level(if enabled {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Warn
    });
}

pub fn enabled() -> bool {
    DEBUG_ENABLED.load(Ordering::Relaxed)
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "on"
    )
}
