use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use linked_list_allocator::LockedHeap;
use uefi::boot::{self, AllocateType, MemoryType, PAGE_SIZE};

use crate::error::{BootError, Result};

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

static HEAP_BASE: AtomicU64 = AtomicU64::new(0);
static HEAP_SIZE: AtomicUsize = AtomicUsize::new(0);

const DEFAULT_HEAP_SIZE: usize = 128 * 1024 * 1024;

pub fn init() -> Result<()> {
    if HEAP_BASE.load(Ordering::Acquire) != 0 {
        return Ok(());
    }

    let size = DEFAULT_HEAP_SIZE;
    let pages = size.div_ceil(PAGE_SIZE);
    let ptr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let base_ptr = ptr.as_ptr();
    let base = base_ptr as u64;

    unsafe {
        ALLOCATOR.lock().init(base_ptr, size);
    }

    HEAP_BASE.store(base, Ordering::Release);
    HEAP_SIZE.store(size, Ordering::Release);
    Ok(())
}

pub fn free() {
    let base = HEAP_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    let size = HEAP_SIZE.load(Ordering::Acquire);
    let pages = size.div_ceil(PAGE_SIZE);
    if let Some(ptr) = NonNull::new(base as *mut u8) {
        let _ = unsafe { boot::free_pages(ptr, pages) };
    }
}
