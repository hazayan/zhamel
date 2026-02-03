use uefi::boot::{self, AllocateType, MemoryType};
use uefi::prelude::Status;
use crate::env::loader::LoaderEnv;
use crate::error::{BootError, Result};
use crate::kernel::elf::LoadedKernelImage;
use crate::kernel::LoadedKernelImagePhys;

const TRAMPOLINE_BYTES: &[u8] = &[
    0x48, 0x89, 0xfc, // mov rsp, rdi
    0xff, 0xd6, // call rsi (copy_finish)
    0x52, // push rdx (kernend)
    0x51, // push rcx (modulep)
    0x4c, 0x89, 0xc0, // mov rax, r8 (pagetable)
    0x0f, 0x22, 0xd8, // mov cr3, rax
    0x4c, 0x89, 0xc8, // mov rax, r9 (entry)
    0xff, 0xe0, // jmp rax
];

type TrampolineFn = extern "sysv64" fn(u64, u64, u64, u64, u64, u64) -> !;

pub fn should_handoff(env: &LoaderEnv) -> bool {
    matches!(
        env.get("zhamel_handoff"),
        Some("1") | Some("YES") | Some("yes") | Some("true")
    )
}

pub fn handoff_to_kernel(
    kernel: LoadedKernelImagePhys,
    modules: &mut [crate::kernel::module::Module],
    efi_map: Option<&[u8]>,
    envp: Option<&[u8]>,
    stage_copy: bool,
) -> Status {
    match prepare_and_handoff(kernel, modules, efi_map, envp, stage_copy) {
        Ok(_) => Status::SUCCESS,
        Err(err) => {
            log::warn!("handoff failed: {}", err);
            Status::ABORTED
        }
    }
}

pub fn handoff_to_kernel_staged(
    kernel: &LoadedKernelImage,
    modules: &mut [crate::kernel::module::Module],
    efi_map: Option<&[u8]>,
    envp: Option<&[u8]>,
) -> Status {
    match prepare_and_handoff_staged(kernel, modules, efi_map, envp) {
        Ok(_) => Status::SUCCESS,
        Err(err) => {
            log::warn!("handoff failed: {}", err);
            Status::ABORTED
        }
    }
}

fn prepare_and_handoff(
    kernel: LoadedKernelImagePhys,
    modules: &mut [crate::kernel::module::Module],
    efi_map: Option<&[u8]>,
    envp: Option<&[u8]>,
    stage_copy: bool,
) -> Result<()> {
    disable_watchdog();
    let stack_top = allocate_stack()?;
    let tramp = allocate_trampoline()?;
    let mut staging = allocate_staging(kernel.size)?;
    let pagetable = allocate_identity_pagetable()?;
    let mut kernend = kernel.base + kernel.size as u64;
    let mut entry = kernel.entry;
    let mut copy_finish = staging.copy_finish;
    if stage_copy {
        stage_kernel_and_modules(&mut staging, &kernel, modules)?;
        if let Some(offset) = kernel_entry_offset(kernel.base, kernel.size, kernel.entry) {
            entry = staging.kernel_base + offset;
            kernend = staging.kernel_base + kernel.size as u64;
            copy_finish = copy_finish_stage as usize as u64;
        } else {
            log::warn!("kernel entry not within image; staging copy disabled");
        }
    }
    let modulep_bytes = crate::kernel::build_kernel_modulep_with_metadata(
        if stage_copy { staging.kernel_base } else { kernel.base },
        kernel.size as u64,
        modules,
        efi_map,
        envp,
    )
    .ok_or(BootError::InvalidData("modulep build failed"))?;
    let modulep_addr = staging.alloc_copy(&modulep_bytes)?;
    let trampoline: TrampolineFn = unsafe { core::mem::transmute(tramp as usize) };

    let memory_map = unsafe { boot::exit_boot_services(None) };
    core::mem::forget(memory_map);

    trampoline(
        stack_top,
        copy_finish,
        kernend,
        modulep_addr,
        pagetable,
        entry,
    );
}

fn prepare_and_handoff_staged(
    kernel: &LoadedKernelImage,
    modules: &mut [crate::kernel::module::Module],
    efi_map: Option<&[u8]>,
    envp: Option<&[u8]>,
) -> Result<()> {
    disable_watchdog();
    let stack_top = allocate_stack()?;
    let tramp = allocate_trampoline()?;
    let mut staging = allocate_staging(kernel.image.len())?;
    let pagetable = allocate_identity_pagetable()?;

    let staged_kernel = staging.alloc_copy(&kernel.image)?;
    let entry = staged_kernel
        .checked_add(kernel_entry_offset(kernel.base, kernel.image.len(), kernel.entry).ok_or(
            BootError::InvalidData("kernel entry not within image"),
        )?)
        .ok_or(BootError::InvalidData("kernel entry overflow"))?;
    let kernend = staged_kernel + kernel.image.len() as u64;
    for module in modules.iter_mut() {
        let staged = staging.alloc_copy(&module.data)?;
        module.set_physical_address(staged);
    }
    let modulep_bytes = crate::kernel::build_kernel_modulep_with_metadata(
        staged_kernel,
        kernel.image.len() as u64,
        modules,
        efi_map,
        envp,
    )
    .ok_or(BootError::InvalidData("modulep build failed"))?;
    let modulep_addr = staging.alloc_copy(&modulep_bytes)?;

    let trampoline: TrampolineFn = unsafe { core::mem::transmute(tramp as usize) };
    let memory_map = unsafe { boot::exit_boot_services(None) };
    core::mem::forget(memory_map);

    trampoline(
        stack_top,
        copy_finish_noop as usize as u64,
        kernend,
        modulep_addr,
        pagetable,
        entry,
    );
}

fn disable_watchdog() {
    if let Err(err) = boot::set_watchdog_timer(0, 0, None) {
        log::warn!("watchdog disable failed: {:?}", err.status());
    }
}

fn allocate_stack() -> Result<u64> {
    let addr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
        .map_err(|err| BootError::Uefi(err.status()))?;
    Ok(addr.as_ptr() as u64 + boot::PAGE_SIZE as u64 - 8)
}

fn allocate_trampoline() -> Result<u64> {
    let addr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
        .map_err(|err| BootError::Uefi(err.status()))?;
    unsafe {
        let dst = addr.as_ptr();
        core::ptr::copy_nonoverlapping(TRAMPOLINE_BYTES.as_ptr(), dst, TRAMPOLINE_BYTES.len());
    }
    Ok(addr.as_ptr() as u64)
}

fn allocate_identity_pagetable() -> Result<u64> {
    const PAGE_SIZE: u64 = 4096;
    const PTE_PRESENT: u64 = 1;
    const PTE_RW: u64 = 1 << 1;
    const PTE_PS: u64 = 1 << 7;
    const TWO_MB: u64 = 2 * 1024 * 1024;

    let addr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 3)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let base = addr.as_ptr() as u64;
    unsafe {
        core::ptr::write_bytes(addr.as_ptr(), 0, (3 * PAGE_SIZE) as usize);
    }

    let pml4 = base as *mut u64;
    let pdpt = (base + PAGE_SIZE) as *mut u64;
    let pd = (base + 2 * PAGE_SIZE) as *mut u64;

    unsafe {
        *pml4 = (pdpt as u64) | PTE_PRESENT | PTE_RW;
        *pdpt = (pd as u64) | PTE_PRESENT | PTE_RW;
        for i in 0..512u64 {
            let entry = (i * TWO_MB) | PTE_PRESENT | PTE_RW | PTE_PS;
            *pd.add(i as usize) = entry;
        }
    }

    Ok(base)
}

struct StagingArea {
    base: u64,
    size: usize,
    cursor: usize,
    copy_finish: u64,
    kernel_base: u64,
}

fn allocate_staging(kernel_size: usize) -> Result<StagingArea> {
    let size = kernel_size.saturating_add(STAGING_SLOP);
    let pages = (size + boot::PAGE_SIZE - 1) / boot::PAGE_SIZE;
    let addr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let base = addr.as_ptr() as u64;
    Ok(StagingArea {
        base,
        size,
        cursor: 0,
        copy_finish: copy_finish_noop as usize as u64,
        kernel_base: base,
    })
}

const STAGING_SLOP: usize = 8 * 1024 * 1024;

extern "C" fn copy_finish_noop() {}

#[repr(C)]
struct CopyContext {
    kernel_base: u64,
    kernel_size: u64,
    staging_base: u64,
}

static mut COPY_CTX: CopyContext = CopyContext {
    kernel_base: 0,
    kernel_size: 0,
    staging_base: 0,
};

extern "C" fn copy_finish_stage() {
    unsafe {
        if COPY_CTX.kernel_size == 0 {
            return;
        }
        let src = COPY_CTX.kernel_base as *const u8;
        let dst = COPY_CTX.staging_base as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, COPY_CTX.kernel_size as usize);
    }
}

fn kernel_entry_offset(base: u64, size: usize, entry: u64) -> Option<u64> {
    let end = base.checked_add(size as u64)?;
    if entry < base || entry >= end {
        return None;
    }
    Some(entry - base)
}

impl StagingArea {
    fn alloc_copy(&mut self, data: &[u8]) -> Result<u64> {
        if data.is_empty() {
            return Err(BootError::InvalidData("staging alloc empty data"));
        }
        let align = 16usize;
        let aligned = (self.cursor + align - 1) & !(align - 1);
        let end = aligned
            .checked_add(data.len())
            .ok_or(BootError::InvalidData("staging alloc overflow"))?;
        if end > self.size {
            return Err(BootError::InvalidData("staging alloc out of space"));
        }
        let dst = (self.base + aligned as u64) as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        self.cursor = end;
        Ok(self.base + aligned as u64)
    }
}

fn stage_kernel_and_modules(
    staging: &mut StagingArea,
    kernel: &LoadedKernelImagePhys,
    modules: &mut [crate::kernel::module::Module],
) -> Result<()> {
    let staged_kernel = staging.alloc_copy_from_phys(kernel.base, kernel.size)?;
    staging.kernel_base = staged_kernel;
    for module in modules.iter_mut() {
        if let Some(src) = module.phys_addr {
            let staged = staging.alloc_copy_from_phys(src, module.data.len())?;
            module.set_physical_address(staged);
        } else {
            let staged = staging.alloc_copy(&module.data)?;
            module.set_physical_address(staged);
        }
    }
    Ok(())
}

impl StagingArea {
    fn alloc_copy_from_phys(&mut self, src: u64, size: usize) -> Result<u64> {
        if size == 0 {
            return Err(BootError::InvalidData("staging copy empty"));
        }
        let align = 16usize;
        let aligned = (self.cursor + align - 1) & !(align - 1);
        let end = aligned
            .checked_add(size)
            .ok_or(BootError::InvalidData("staging alloc overflow"))?;
        if end > self.size {
            return Err(BootError::InvalidData("staging alloc out of space"));
        }
        let dst = (self.base + aligned as u64) as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src as *const u8, dst, size);
        }
        self.cursor = end;
        Ok(self.base + aligned as u64)
    }
}
