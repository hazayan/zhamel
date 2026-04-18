extern crate alloc;

use crate::env::loader::LoaderEnv;
use crate::error::{BootError, Result};
use crate::kernel::elf::LoadedKernelImage;
use crate::kernel::types::{
    MODINFO_ADDR, MODINFO_END, MODINFO_METADATA, MODINFO_NAME, MODINFO_SIZE, MODINFO_TYPE,
    ModInfoMd,
};
use crate::kernel::{KERNEL_PHYS_BASE, LoadedKernelImagePhys};
use alloc::string::String;
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::prelude::Status;

#[allow(dead_code)]
const GDT_CODE64: u64 = 0x00af9a000000ffff;
#[allow(dead_code)]
const GDT_DATA64: u64 = 0x00af92000000ffff;
#[allow(dead_code)]
const KERNBASE: u64 = 0xffff_ffff_8000_0000;
const PT_LOAD: u32 = 1;

type TrampolineFn = extern "sysv64" fn(u64, u64, u64, u64, u64, u64) -> !;

pub fn should_handoff(env: &LoaderEnv) -> bool {
    !matches!(
        env.get("zhamel_handoff"),
        Some("0") | Some("NO") | Some("no") | Some("false")
    )
}

pub fn handoff_to_kernel(
    kernel: LoadedKernelImagePhys,
    modules: &mut [crate::kernel::module::Module],
    efi_map: Option<&[u8]>,
    envp: Option<&[u8]>,
    howto: u32,
    stage_copy: bool,
) -> Status {
    match prepare_and_handoff(kernel, modules, efi_map, envp, howto, stage_copy) {
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
    howto: u32,
) -> Status {
    match prepare_and_handoff_staged(kernel, modules, efi_map, envp, howto) {
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
    howto: u32,
    stage_copy: bool,
) -> Result<()> {
    disable_watchdog();
    let stack_top = if stage_copy {
        allocate_stack_below_1gb()?
    } else {
        allocate_stack()?
    };
    let module_bytes = if stage_copy {
        modules.iter().map(|m| m.data_len).sum()
    } else {
        0usize
    };
    let mut staging = allocate_staging(kernel.size.saturating_add(module_bytes))?;
    let mut kernend = kernel.base + kernel.size as u64;
    let mut copy_finish = staging.copy_finish;
    let stage_offset = if stage_copy {
        staging.base.saturating_sub(KERNEL_PHYS_BASE)
    } else {
        0
    };
    let phys_base = if stage_copy {
        0
    } else {
        kernel
            .base
            .checked_sub(KERNEL_PHYS_BASE)
            .ok_or(BootError::InvalidData("kernel base below KERNEL_PHYS_BASE"))?
    };
    kernend = kernend.max(phys_base.saturating_add(max_module_end_offset(modules, phys_base)));
    let entry = select_kernel_entry(&kernel.info, kernel.entry);
    let _entry_offset =
        kernel_entry_offset_with_phdrs(&kernel.info, kernel.base, kernel.size, entry)
            .ok_or(BootError::InvalidData("kernel entry not within image"))?;
    let tramp = allocate_trampoline(if stage_copy { Some(0x3fff_ffff) } else { None })?;
    let jump_entry = entry;
    if stage_copy {
        stage_kernel_and_modules(&mut staging, &kernel, modules)?;
        // Use the separate trampoline stack (outside staging) to avoid clobber.
        kernend = KERNEL_PHYS_BASE + kernel.size as u64;
        copy_finish = copy_finish_stage as usize as u64;
        let staging_end = staging.base.saturating_add(staging.size as u64);
        for module in modules.iter_mut() {
            if let Some(addr) = module.phys_addr {
                if addr >= staging.base && addr < staging_end {
                    module.set_physical_address(addr.saturating_sub(stage_offset));
                }
            }
        }
        kernend = kernend.max(max_module_end_offset(modules, 0));
    }
    let modulep_base = if stage_copy { 0 } else { phys_base };
    let kernel_phys_base = if stage_copy {
        KERNEL_PHYS_BASE
    } else {
        kernel.base
    };
    // Stage environment bytes separately; the kernel expects ENVP to be a
    // pointer to the env string, not the string content itself.
    let envp_phys = if let Some(env_bytes) = envp {
        if !env_bytes.is_empty() {
            if stage_copy {
                let staged = staging.alloc_copy(env_bytes)?;
                Some(staged.saturating_sub(stage_offset))
            } else {
                let addr = allocate_modulep_at(kernend, env_bytes)?;
                kernend = addr + md_align(env_bytes.len() as u64);
                Some(addr.saturating_sub(phys_base))
            }
        } else {
            None
        }
    } else {
        None
    };
    let mut modulep_bytes = crate::kernel::build_kernel_modulep_with_metadata_relocated(
        kernel_phys_base,
        kernel.size as u64,
        modules,
        efi_map,
        envp_phys,
        phys_base,
        0,
        0,
        howto,
    )
    .ok_or(BootError::InvalidData("modulep build failed"))?;
    let modulep_addr = if stage_copy {
        let staging_addr = staging.alloc_copy(&modulep_bytes)?;
        staging_addr.saturating_sub(stage_offset)
    } else {
        allocate_modulep_at(kernend, &modulep_bytes)?
    };
    if modulep_addr < modulep_base {
        return Err(BootError::InvalidData("modulep below modulep base"));
    }
    let modulep_offset = modulep_addr;
    let _kernel_phys_base = phys_base.saturating_add(KERNEL_PHYS_BASE);
    let modulep_end = md_align(modulep_addr.saturating_add(modulep_bytes.len() as u64));
    let kernend_offset = modulep_end.max(max_module_end_offset(modules, phys_base));
    if modulep_offset > u32::MAX as u64 || kernend_offset > u32::MAX as u64 {
        return Err(BootError::InvalidData("modulep/kernend offset overflow"));
    }
    modulep_bytes = crate::kernel::build_kernel_modulep_with_metadata_relocated(
        if stage_copy {
            KERNEL_PHYS_BASE
        } else {
            kernel.base
        },
        kernel.size as u64,
        modules,
        efi_map,
        envp_phys,
        phys_base,
        modulep_offset,
        kernend_offset,
        howto,
    )
    .ok_or(BootError::InvalidData("modulep build failed"))?;
    log::warn!(
        "modulep: offsets modulep=0x{:x} kernend=0x{:x}",
        modulep_offset,
        kernend_offset
    );
    log_modulep_summary(&modulep_bytes);
    let modulep_dst = if stage_copy {
        modulep_addr.saturating_add(stage_offset)
    } else {
        modulep_addr
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            modulep_bytes.as_ptr(),
            modulep_dst as *mut u8,
            modulep_bytes.len(),
        );
    }
    if stage_copy {
        unsafe {
            COPY_CTX.kernel_base = staging.base;
            COPY_CTX.kernel_size = md_align(staging.cursor as u64);
            COPY_CTX.staging_base = KERNEL_PHYS_BASE;
        }
    }
    let stack_phys = stack_top;
    let stack_arg = stack_phys;
    let identity_gb = compute_identity_map_gb(max_phys_addr_for_handoff(
        kernel.base,
        kernel.size as u64,
        &staging,
        &modulep_bytes,
        modulep_addr,
        stack_phys,
        tramp.addr,
        tramp.len,
        modules,
    ));
    let high_map_size = modulep_addr
        .saturating_add(modulep_bytes.len() as u64)
        .saturating_sub(modulep_base);
    log::warn!(
        "handoff params: stage_copy={} staging_base=0x{:x} kernel_base=0x{:x} phys_base=0x{:x} modulep_addr=0x{:x} modulep_off=0x{:x} kernend_off=0x{:x} map_size=0x{:x}",
        stage_copy,
        staging.base,
        if stage_copy {
            KERNEL_PHYS_BASE
        } else {
            kernel.base
        },
        phys_base,
        modulep_addr,
        modulep_offset,
        kernend_offset,
        high_map_size
    );
    let pagetable = if stage_copy {
        allocate_pagetable_staged()?
    } else {
        allocate_pagetable(
            &kernel.info,
            if stage_copy {
                KERNEL_PHYS_BASE
            } else {
                kernel.base
            },
            kernel.size,
            entry,
            identity_gb,
            high_map_size,
        )?
    };
    let trampoline: TrampolineFn = unsafe { core::mem::transmute(tramp.addr as usize) };

    let memory_map = unsafe { boot::exit_boot_services(None) };
    core::mem::forget(memory_map);

    trampoline(
        stack_arg,
        copy_finish,
        kernend_offset,
        modulep_offset,
        pagetable,
        jump_entry,
    );
}

fn prepare_and_handoff_staged(
    kernel: &LoadedKernelImage,
    modules: &mut [crate::kernel::module::Module],
    efi_map: Option<&[u8]>,
    envp: Option<&[u8]>,
    howto: u32,
) -> Result<()> {
    disable_watchdog();
    let stack_top = allocate_stack_below_1gb()?;
    crate::kernel::prepare_modules_for_handoff(modules)?;
    let module_bytes: usize = modules.iter().map(|m| m.data_len).sum();
    let mut staging = allocate_staging(kernel.image.len().saturating_add(module_bytes))?;
    let stage_offset = staging.base.saturating_sub(KERNEL_PHYS_BASE);
    let entry = select_kernel_entry(&kernel.info, kernel.entry);

    let _staged_kernel = staging.alloc_copy_at(0, &kernel.image)?;
    // Use the separate trampoline stack (outside staging) to avoid clobber.
    let _entry_offset =
        kernel_entry_offset_with_phdrs(&kernel.info, kernel.base, kernel.image.len(), entry)
            .ok_or(BootError::InvalidData("kernel entry not within image"))?;
    let tramp = allocate_trampoline(Some(0x3fff_ffff))?;
    let _kernend = KERNEL_PHYS_BASE + kernel.image.len() as u64;
    for module in modules.iter_mut() {
        if module.data_len == 0 {
            continue;
        }
        let staged = if let Some(src) = module.phys_addr {
            staging.alloc_copy_from_phys(src, module.data_len)?
        } else {
            staging.alloc_copy(&module.data)?
        };
        module.set_physical_address(staged.saturating_sub(stage_offset));
    }
    let phys_base = 0u64;
    let jump_entry = entry;
    let kernel_phys_base = KERNEL_PHYS_BASE;
    // Stage environment bytes separately; the kernel expects ENVP to be a
    // pointer to the env string, not the string content itself.
    let envp_phys = if let Some(env_bytes) = envp {
        if !env_bytes.is_empty() {
            let staged = staging.alloc_copy(env_bytes)?;
            let phys = staged.saturating_sub(stage_offset);
            log::warn!(
                "envp: staged {} bytes at phys 0x{:x}",
                env_bytes.len(),
                phys
            );
            Some(phys)
        } else {
            None
        }
    } else {
        None
    };
    let mut modulep_bytes = crate::kernel::build_kernel_modulep_with_metadata_relocated(
        kernel_phys_base,
        kernel.image.len() as u64,
        modules,
        efi_map,
        envp_phys,
        phys_base,
        0,
        0,
        howto,
    )
    .ok_or(BootError::InvalidData("modulep build failed"))?;
    let modulep_addr = staging
        .alloc_copy(&modulep_bytes)?
        .saturating_sub(stage_offset);
    let modulep_offset = modulep_addr;
    let kernel_phys_base = phys_base.saturating_add(KERNEL_PHYS_BASE);
    let modulep_end = md_align(modulep_addr.saturating_add(modulep_bytes.len() as u64));
    let kernend_offset = modulep_end.max(max_module_end_offset(modules, phys_base));
    if modulep_offset > u32::MAX as u64 || kernend_offset > u32::MAX as u64 {
        return Err(BootError::InvalidData("modulep/kernend offset overflow"));
    }
    modulep_bytes = crate::kernel::build_kernel_modulep_with_metadata_relocated(
        kernel_phys_base,
        kernel.image.len() as u64,
        modules,
        efi_map,
        envp_phys,
        phys_base,
        modulep_offset,
        kernend_offset,
        howto,
    )
    .ok_or(BootError::InvalidData("modulep build failed"))?;
    log::warn!(
        "modulep: offsets modulep=0x{:x} kernend=0x{:x}",
        modulep_offset,
        kernend_offset
    );
    log_modulep_summary(&modulep_bytes);
    let modulep_dst = modulep_addr.saturating_add(stage_offset);
    unsafe {
        core::ptr::copy_nonoverlapping(
            modulep_bytes.as_ptr(),
            modulep_dst as *mut u8,
            modulep_bytes.len(),
        );
    }
    unsafe {
        COPY_CTX.kernel_base = staging.base;
        COPY_CTX.kernel_size = md_align(staging.cursor as u64);
        COPY_CTX.staging_base = KERNEL_PHYS_BASE;
    }
    let stack_phys = stack_top;
    let stack_arg = stack_phys;
    let _identity_gb = compute_identity_map_gb(max_phys_addr_for_handoff(
        KERNEL_PHYS_BASE,
        kernel.image.len() as u64,
        &staging,
        &modulep_bytes,
        modulep_addr,
        stack_phys,
        tramp.addr,
        tramp.len,
        modules,
    ));
    let high_map_size = modulep_addr
        .saturating_add(modulep_bytes.len() as u64)
        .saturating_sub(0);
    log::warn!(
        "handoff params: stage_copy=true staging_base=0x{:x} kernel_base=0x{:x} phys_base=0x{:x} modulep_addr=0x{:x} modulep_off=0x{:x} kernend_off=0x{:x} map_size=0x{:x}",
        staging.base,
        kernel_phys_base,
        phys_base,
        modulep_addr,
        modulep_offset,
        kernend_offset,
        high_map_size
    );
    let pagetable = allocate_pagetable_staged()?;

    let trampoline: TrampolineFn = unsafe { core::mem::transmute(tramp.addr as usize) };
    let memory_map = unsafe { boot::exit_boot_services(None) };
    core::mem::forget(memory_map);

    trampoline(
        stack_arg,
        copy_finish_stage as usize as u64,
        kernend_offset,
        modulep_offset,
        pagetable,
        jump_entry,
    );
}

fn disable_watchdog() {
    if let Err(err) = boot::set_watchdog_timer(0, 0, None) {
        log::warn!("watchdog disable failed: {:?}", err.status());
    }
}

fn log_modulep_summary(buf: &[u8]) {
    if buf.is_empty() {
        log::warn!("modulep: empty");
        return;
    }
    let mut offset = 0usize;
    let mut count = 0u32;
    let mut mod_name: Option<alloc::string::String> = None;
    let mut mod_type: Option<alloc::string::String> = None;
    let mut mod_addr: Option<u64> = None;
    let mut mod_logged = 0u32;
    while offset + 8 <= buf.len() && count < 64 {
        let type_ = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        let size = u32::from_le_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]) as usize;
        if type_ == MODINFO_NAME && size > 0 && offset + 8 + size <= buf.len() {
            let raw = &buf[offset + 8..offset + 8 + size];
            let len = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            mod_name = Some(String::from_utf8_lossy(&raw[..len]).into_owned());
            mod_type = None;
            mod_addr = None;
        } else if type_ == MODINFO_TYPE && size > 0 && offset + 8 + size <= buf.len() {
            let raw = &buf[offset + 8..offset + 8 + size];
            let len = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            mod_type = Some(String::from_utf8_lossy(&raw[..len]).into_owned());
        } else if type_ == MODINFO_ADDR && offset + 8 + size <= buf.len() {
            let value = if size >= 8 {
                u64::from_le_bytes([
                    buf[offset + 8],
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                    buf[offset + 12],
                    buf[offset + 13],
                    buf[offset + 14],
                    buf[offset + 15],
                ])
            } else {
                u64::from(u32::from_le_bytes([
                    buf[offset + 8],
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                ]))
            };
            mod_addr = Some(value);
        } else if type_ == MODINFO_SIZE && offset + 8 + size <= buf.len() {
            let value = if size >= 8 {
                u64::from_le_bytes([
                    buf[offset + 8],
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                    buf[offset + 12],
                    buf[offset + 13],
                    buf[offset + 14],
                    buf[offset + 15],
                ])
            } else {
                u64::from(u32::from_le_bytes([
                    buf[offset + 8],
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                ]))
            };
            if mod_logged < 8 {
                if let (Some(name), Some(kind), Some(addr)) =
                    (mod_name.as_deref(), mod_type.as_deref(), mod_addr)
                {
                    log::warn!(
                        "modulep: mod name={} type={} addr=0x{:x} size=0x{:x}",
                        name,
                        kind,
                        addr,
                        value
                    );
                    mod_logged += 1;
                }
            }
        }
        if type_ & MODINFO_METADATA == MODINFO_METADATA && size >= 4 {
            let md_type = type_ & !MODINFO_METADATA;
            let value = if size >= 8 && offset + 16 <= buf.len() {
                u64::from_le_bytes([
                    buf[offset + 8],
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                    buf[offset + 12],
                    buf[offset + 13],
                    buf[offset + 14],
                    buf[offset + 15],
                ])
            } else {
                u64::from(u32::from_le_bytes([
                    buf[offset + 8],
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                ]))
            };
            let label = match md_type {
                x if x == ModInfoMd::Modulep as u32 => "Modulep",
                x if x == ModInfoMd::Kernend as u32 => "Kernend",
                x if x == ModInfoMd::Howto as u32 => "Howto",
                _ => "Metadata",
            };
            log::warn!(
                "modulep: md={} type=0x{:x} size=0x{:x} value=0x{:x}",
                label,
                md_type,
                size,
                value
            );
        }
        let mut next = offset + 8 + size;
        let rem = next % 8;
        if rem != 0 {
            next += 8 - rem;
        }
        if next <= offset {
            log::warn!("modulep: invalid next offset");
            break;
        }
        offset = next;
        count += 1;
        if type_ == MODINFO_END {
            break;
        }
    }
    if count >= 64 {
        log::warn!("modulep: truncated after 64 entries");
    }
}

fn allocate_stack() -> Result<u64> {
    allocate_stack_with_max(0xffff_ffff)
}

fn allocate_stack_below_1gb() -> Result<u64> {
    allocate_stack_with_max(0x3fff_ffff)
}

fn allocate_stack_with_max(max_addr: u64) -> Result<u64> {
    let addr = boot::allocate_pages(
        AllocateType::MaxAddress(max_addr),
        MemoryType::LOADER_DATA,
        1,
    )
    .map_err(|err| BootError::Uefi(err.status()))?;
    Ok(addr.as_ptr() as u64 + boot::PAGE_SIZE as u64 - 8)
}

fn md_align(addr: u64) -> u64 {
    let mask = boot::PAGE_SIZE as u64 - 1;
    (addr + mask) & !mask
}

fn max_module_end_offset(modules: &[crate::kernel::module::Module], phys_base: u64) -> u64 {
    modules
        .iter()
        .filter_map(|module| {
            let addr = module.phys_addr?;
            if addr < phys_base {
                return None;
            }
            let offset = addr - phys_base;
            Some(md_align(offset.saturating_add(module.data_len as u64)))
        })
        .max()
        .unwrap_or(0)
}

struct TrampolineImage {
    bytes: alloc::vec::Vec<u8>,
}

struct Trampoline {
    addr: u64,
    len: usize,
}

fn allocate_trampoline(max_addr: Option<u64>) -> Result<Trampoline> {
    let image = build_trampoline()?;
    let pages = (image.bytes.len() + boot::PAGE_SIZE - 1) / boot::PAGE_SIZE;
    let alloc = match max_addr {
        Some(limit) => AllocateType::MaxAddress(limit),
        None => AllocateType::AnyPages,
    };
    let addr = boot::allocate_pages(alloc, MemoryType::LOADER_DATA, pages)
        .map_err(|err| BootError::Uefi(err.status()))?;
    unsafe {
        let dst = addr.as_ptr();
        core::ptr::copy_nonoverlapping(image.bytes.as_ptr(), dst, image.bytes.len());
    }
    Ok(Trampoline {
        addr: addr.as_ptr() as u64,
        len: image.bytes.len(),
    })
}

fn build_trampoline() -> Result<TrampolineImage> {
    let mut code: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let emit_outb = |code: &mut alloc::vec::Vec<u8>, port: u16, value: u8| {
        code.extend_from_slice(&[0x66, 0xba]); // mov dx, imm16
        code.extend_from_slice(&port.to_le_bytes());
        code.extend_from_slice(&[0xb0, value]); // mov al, imm8
        code.push(0xee); // out dx, al
    };
    // FreeBSD amd64_tramp.S equivalent
    // init COM1 and emit 'Z'
    emit_outb(&mut code, 0x3f8 + 1, 0x00);
    emit_outb(&mut code, 0x3f8 + 3, 0x80);
    emit_outb(&mut code, 0x3f8 + 0, 0x01);
    emit_outb(&mut code, 0x3f8 + 1, 0x00);
    emit_outb(&mut code, 0x3f8 + 3, 0x03);
    emit_outb(&mut code, 0x3f8 + 2, 0xc7);
    emit_outb(&mut code, 0x3f8 + 4, 0x0b);
    emit_outb(&mut code, 0x3f8 + 0, b'Z');
    code.push(0xfa); // cli
    code.extend_from_slice(&[0x48, 0x89, 0xfc]); // mov rsp, rdi
    code.extend_from_slice(&[0x52, 0x41, 0x5c]); // push rdx; pop r12
    code.extend_from_slice(&[0x51, 0x41, 0x5d]); // push rcx; pop r13
    code.extend_from_slice(&[0x41, 0x50, 0x41, 0x5e]); // push r8; pop r14
    code.extend_from_slice(&[0x41, 0x51, 0x41, 0x5f]); // push r9; pop r15
    emit_outb(&mut code, 0x3f8 + 0, b'C');
    code.extend_from_slice(&[0xff, 0xd6]); // call rsi
    emit_outb(&mut code, 0x3f8 + 0, b'c');
    // Diagnostic: check if copy_finish corrupted r14 (pagetable base).
    // Emit r14 low byte as two hex nibbles so we can see the exact value.
    // high nibble of r14's low byte:
    code.extend_from_slice(&[0x4c, 0x89, 0xf0]); // mov rax, r14
    code.extend_from_slice(&[0x24, 0xff]); // and al, 0xff
    code.extend_from_slice(&[0xc0, 0xe8, 0x04]); // shr al, 4
    code.extend_from_slice(&[0x04, 0x30]); // add al, '0'
    code.extend_from_slice(&[0x3c, 0x3a]); // cmp al, ':'
    {
        // if al >= ':', add 'a'-'0'-10 = 39
        let skip = 2u8; // bytes in the add al, 39 instruction
        code.extend_from_slice(&[0x72, skip]); // jb .skip_hex
        code.extend_from_slice(&[0x04, 39]); // add al, 39  ('a'-'0'-10)
    }
    code.extend_from_slice(&[0xba, 0xf8, 0x03, 0x00, 0x00]); // mov edx, 0x3f8
    code.extend_from_slice(&[0xee]); // out dx, al
    // low nibble of r14's low byte:
    code.extend_from_slice(&[0x4c, 0x89, 0xf0]); // mov rax, r14
    code.extend_from_slice(&[0x24, 0x0f]); // and al, 0x0f
    code.extend_from_slice(&[0x04, 0x30]); // add al, '0'
    code.extend_from_slice(&[0x3c, 0x3a]); // cmp al, ':'
    {
        let skip = 2u8;
        code.extend_from_slice(&[0x72, skip]); // jb .skip_hex
        code.extend_from_slice(&[0x04, 39]); // add al, 39
    }
    code.extend_from_slice(&[0xee]); // out dx, al (edx still 0x3f8)
    code.extend_from_slice(&[0x41, 0x54]); // push r12 (kernend)
    emit_outb(&mut code, 0x3f8 + 0, b'1');
    code.extend_from_slice(&[0x49, 0xc1, 0xe5, 0x20]); // shl r13, 32
    emit_outb(&mut code, 0x3f8 + 0, b'2');
    code.extend_from_slice(&[0x41, 0x55]); // push r13 (modulep << 32)
    emit_outb(&mut code, 0x3f8 + 0, b'3');
    code.extend_from_slice(&[0x41, 0x57]); // push r15 (entry)
    emit_outb(&mut code, 0x3f8 + 0, b'4');
    // Switch to our staged page tables and enter the kernel immediately.
    // Keep this tail byte-for-byte close to FreeBSD's amd64_tramp.S: once CR3
    // changes, avoid diagnostics that clobber the register state seen by locore.
    code.extend_from_slice(&[0x4c, 0x89, 0xf0]); // mov rax, r14
    code.extend_from_slice(&[0x0f, 0x22, 0xd8]); // mov cr3, rax  (switch page tables)
    code.push(0xc3); // ret
    Ok(TrampolineImage { bytes: code })
}

fn allocate_pagetable(
    info: &crate::kernel::elf::Elf64Info,
    kernel_base: u64,
    kernel_size: usize,
    kernel_entry: u64,
    identity_gb: u64,
    high_map_size: u64,
) -> Result<u64> {
    const PAGE_SIZE: u64 = 4096;
    const PTE_PRESENT: u64 = 1;
    const PTE_RW: u64 = 1 << 1;
    const PTE_PS: u64 = 1 << 7;
    const TWO_MB: u64 = 2 * 1024 * 1024;
    const ONE_GB: u64 = 1024 * 1024 * 1024;
    let id_map_gb = if identity_gb < 4 { 4 } else { identity_gb };
    let pd_count = id_map_gb as usize;
    let pages = 3 + pd_count;
    let addr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let base = addr.as_ptr() as u64;
    unsafe {
        core::ptr::write_bytes(addr.as_ptr(), 0, (pages as u64 * PAGE_SIZE) as usize);
    }

    let pml4 = base as *mut u64;
    let pdpt_low = (base + PAGE_SIZE) as *mut u64;
    let pdpt_high = (base + 2 * PAGE_SIZE) as *mut u64;
    let pd_base = base + 3 * PAGE_SIZE;

    unsafe {
        *pml4 = (pdpt_low as u64) | PTE_PRESENT | PTE_RW;
        *pml4.add(511) = (pdpt_high as u64) | PTE_PRESENT | PTE_RW;
        for i in 0..pd_count {
            let pd = (pd_base + (i as u64 * PAGE_SIZE)) as *mut u64;
            *pdpt_low.add(i) = (pd as u64) | PTE_PRESENT | PTE_RW;
            for j in 0..512u64 {
                let entry = (i as u64 * ONE_GB) + (j * TWO_MB) | PTE_PRESENT | PTE_RW | PTE_PS;
                *pd.add(j as usize) = entry;
            }
        }
    }

    map_kernel_image_range(
        info,
        kernel_base,
        kernel_size,
        kernel_entry,
        high_map_size,
        pml4,
        pdpt_high,
    )?;

    Ok(base)
}

fn allocate_pagetable_staged() -> Result<u64> {
    const PAGE_SIZE: u64 = 4096;
    const PTE_PRESENT: u64 = 1;
    const PTE_RW: u64 = 1 << 1;
    const PTE_PS: u64 = 1 << 7;
    const TWO_MB: u64 = 2 * 1024 * 1024;
    const ONE_GB: u64 = 1024 * 1024 * 1024;
    // 2GB identity map: PML4 + PDP + PD0 (0..1GB) + PD1 (1GB..2GB).
    // The kernel's amd64_loadaddr() reads page table pages via the identity
    // map (2GB cycling), so the pages must be below 2GB.  They must also
    // be above the full copy_finish destination range to avoid being
    // overwritten when the trampoline copies the staged kernel.
    let pages = 4;
    // copy_finish writes COPY_CTX.kernel_size bytes to COPY_CTX.staging_base.
    // The page tables must be above that entire range.
    let copy_dest_end = unsafe { COPY_CTX.staging_base + COPY_CTX.kernel_size };
    let kernel_dest_ceil = (copy_dest_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    log::warn!(
        "staged pagetable: copy_dest_end=0x{:x} ceil=0x{:x}",
        copy_dest_end,
        kernel_dest_ceil
    );
    let addr = {
        // Allocate below 2GB.  If the result overlaps the copy destination,
        // free it and retry (UEFI will pick a different spot).
        let mut attempts = 0u32;
        loop {
            let a = boot::allocate_pages(
                AllocateType::MaxAddress(0x7fff_ffff),
                MemoryType::LOADER_DATA,
                pages,
            )
            .map_err(|err| BootError::Uefi(err.status()))?;
            let base = a.as_ptr() as u64;
            if base >= kernel_dest_ceil {
                break a; // safe: above copy destination, below 2GB
            }
            // Overlaps with copy destination — free and retry.
            unsafe {
                let _ = boot::free_pages(a, pages);
            }
            attempts += 1;
            if attempts > 8 {
                return Err(BootError::InvalidData(
                    "cannot allocate staged page tables outside kernel destination",
                ));
            }
        }
    };
    let raw_base = addr.as_ptr() as u64;
    log::warn!(
        "staged pagetable: raw_base=0x{:x} low_bits=0x{:x}",
        raw_base,
        raw_base & 0xFFF
    );
    let base = raw_base & !0xFFF; // ensure page-aligned for CR3
    unsafe {
        core::ptr::write_bytes(base as *mut u8, 0, (pages as u64 * PAGE_SIZE) as usize);
    }
    let pml4 = base as *mut u64;
    let pdpt = (base + PAGE_SIZE) as *mut u64;
    let pd0 = (base + 2 * PAGE_SIZE) as *mut u64;
    let pd1 = (base + 3 * PAGE_SIZE) as *mut u64;
    unsafe {
        for i in 0..512usize {
            *pml4.add(i) = (pdpt as u64) | PTE_PRESENT | PTE_RW;
        }
        // PDP: cycle pd0 (even) / pd1 (odd) for all 512 slots.
        // High kernel VAs (PDP slot 510, even) → pd0 (0..1GB) where the
        // kernel sits.  Low VAs also wrap to 0..2GB.  Page tables are
        // within 0..2GB so they are identity-mapped.
        for i in 0..512usize {
            *pdpt.add(i) = (if i % 2 == 0 { pd0 } else { pd1 } as u64) | PTE_PRESENT | PTE_RW;
        }
        for i in 0..512usize {
            *pd0.add(i) = (i as u64 * TWO_MB) | PTE_PRESENT | PTE_RW | PTE_PS;
            *pd1.add(i) = (ONE_GB + (i as u64 * TWO_MB)) | PTE_PRESENT | PTE_RW | PTE_PS;
        }
    }
    Ok(base)
}

fn max_phys_addr_for_handoff(
    kernel_base: u64,
    kernel_size: u64,
    staging: &StagingArea,
    modulep_bytes: &[u8],
    modulep_addr: u64,
    stack_phys: u64,
    tramp: u64,
    tramp_len: usize,
    modules: &[crate::kernel::module::Module],
) -> u64 {
    let mut max_addr = kernel_base.saturating_add(kernel_size);
    let staging_end = staging.base.saturating_add(staging.size as u64);
    if staging_end > max_addr {
        max_addr = staging_end;
    }
    let modulep_end = modulep_addr.saturating_add(modulep_bytes.len() as u64);
    if modulep_end > max_addr {
        max_addr = modulep_end;
    }
    let stack_base = stack_phys
        .saturating_add(8)
        .saturating_sub(boot::PAGE_SIZE as u64);
    if stack_base.saturating_add(boot::PAGE_SIZE as u64) > max_addr {
        max_addr = stack_base.saturating_add(boot::PAGE_SIZE as u64);
    }
    let tramp_end = tramp.saturating_add(tramp_len as u64);
    if tramp_end > max_addr {
        max_addr = tramp_end;
    }
    for module in modules {
        if let Some(phys) = module.phys_addr {
            let end = phys.saturating_add(module.data_len as u64);
            if end > max_addr {
                max_addr = end;
            }
        }
    }
    max_addr
}

fn compute_identity_map_gb(max_phys: u64) -> u64 {
    if max_phys == 0 {
        return 4;
    }
    let gb = (max_phys + (1 << 30) - 1) >> 30;
    if gb < 4 { 4 } else { gb }
}

fn map_kernel_image_range(
    info: &crate::kernel::elf::Elf64Info,
    kernel_base: u64,
    kernel_size: usize,
    kernel_entry: u64,
    high_map_size: u64,
    _pml4: *mut u64,
    pdpt: *mut u64,
) -> Result<()> {
    const PTE_PRESENT: u64 = 1;
    const PTE_RW: u64 = 1 << 1;
    const PTE_PS: u64 = 1 << 7; // 2MB page
    const TWO_MB: u64 = 2 * 1024 * 1024;
    const PT_LOAD: u32 = 1;
    const KERNBASE: u64 = 0xffff_ffff_8000_0000;
    const KERNEL_PHYS_BASE: u64 = 0x20_0000;

    let mut found = false;
    for phdr in &info.program_headers {
        if phdr.p_type != PT_LOAD || phdr.memsz == 0 {
            continue;
        }
        found = true;
    }
    if !found {
        return Err(BootError::InvalidData("missing PT_LOAD segments"));
    }

    // Map using 2MB pages so the kernel's amd64_loadaddr() can read
    // the physical address directly from the PDE (it expects PG_PS).
    let map_range_2m = |pdpt: *mut u64, vstart: u64, pstart: u64, size: u64| -> Result<()> {
        let mut vaddr = vstart & !(TWO_MB - 1);
        let total = (size + TWO_MB - 1) & !(TWO_MB - 1);
        let mut paddr = pstart & !(TWO_MB - 1);
        let mut mapped = 0u64;
        while mapped < total {
            let pml4_idx = ((vaddr >> 39) & 0x1ff) as usize;
            if pml4_idx != 511 {
                return Err(BootError::InvalidData("kernel vaddr outside higher-half"));
            }
            let pdpt_idx = ((vaddr >> 30) & 0x1ff) as usize;
            let pd_idx = ((vaddr >> 21) & 0x1ff) as usize;

            let mut pd_addr = 0u64;
            unsafe {
                let entry = *pdpt.add(pdpt_idx);
                if entry & PTE_PRESENT != 0 {
                    pd_addr = entry & !0xfff;
                }
            }
            if pd_addr == 0 {
                let pd_page =
                    boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
                        .map_err(|err| BootError::Uefi(err.status()))?;
                let pd_addr_new = pd_page.as_ptr() as u64;
                unsafe {
                    core::ptr::write_bytes(pd_page.as_ptr(), 0, 4096);
                    *pdpt.add(pdpt_idx) = pd_addr_new | PTE_PRESENT | PTE_RW;
                }
                pd_addr = pd_addr_new;
            }

            // Set 2MB PDE
            unsafe {
                let pd = pd_addr as *mut u64;
                *pd.add(pd_idx) = paddr | PTE_PRESENT | PTE_RW | PTE_PS;
            }

            vaddr = vaddr.saturating_add(TWO_MB);
            paddr = paddr.saturating_add(TWO_MB);
            mapped = mapped.saturating_add(TWO_MB);
        }
        Ok(())
    };

    let kernel_virt_base = KERNBASE.saturating_add(KERNEL_PHYS_BASE);
    let map_size = core::cmp::max(
        2 * 1024 * 1024 * 1024,
        core::cmp::max(
            KERNEL_PHYS_BASE.saturating_add(kernel_size as u64),
            high_map_size,
        ),
    );
    let kernel_range_end = KERNBASE.checked_add(map_size);
    if kernel_entry < kernel_virt_base || kernel_range_end.is_some_and(|end| kernel_entry >= end) {
        return Err(BootError::InvalidData("kernel entry not within image"));
    }

    let phys_base = kernel_base.saturating_sub(KERNEL_PHYS_BASE);
    log::warn!(
        "handoff high map: phys_base=0x{:x} size=0x{:x}",
        phys_base,
        map_size
    );
    map_range_2m(pdpt, KERNBASE, phys_base, map_size)?;

    Ok(())
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

fn allocate_modulep_at(base: u64, data: &[u8]) -> Result<u64> {
    if data.is_empty() {
        return Err(BootError::InvalidData("modulep empty"));
    }
    let size = data.len();
    let pages = (size + boot::PAGE_SIZE - 1) / boot::PAGE_SIZE;
    let aligned = (base + boot::PAGE_SIZE as u64 - 1) & !(boot::PAGE_SIZE as u64 - 1);
    let addr = match boot::allocate_pages(
        AllocateType::Address(aligned),
        MemoryType::LOADER_DATA,
        pages,
    ) {
        Ok(addr) => addr,
        Err(_) => boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
            .map_err(|err| BootError::Uefi(err.status()))?,
    };
    let addr = addr.as_ptr() as u64;
    if addr < base {
        return Err(BootError::InvalidData("modulep allocation below base"));
    }
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, size);
    }
    Ok(addr)
}

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

fn kernel_entry_offset_with_phdrs(
    info: &crate::kernel::elf::Elf64Info,
    base: u64,
    size: usize,
    entry: u64,
) -> Option<u64> {
    if let Some(offset) = kernel_entry_offset(base, size, entry) {
        return Some(offset);
    }
    let end = base.checked_add(size as u64)?;
    for phdr in &info.program_headers {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        let vbase = phdr.vaddr;
        let vend = vbase.saturating_add(phdr.memsz);
        if entry < vbase || entry >= vend {
            continue;
        }
        let offset = phdr.offset.saturating_add(entry.saturating_sub(vbase));
        if offset < size as u64 {
            return Some(offset);
        }
        let pbase = if phdr.paddr != 0 {
            phdr.paddr
        } else {
            phdr.vaddr
        };
        let entry_phys = pbase.saturating_add(entry.saturating_sub(vbase));
        if entry_phys < base || entry_phys >= end {
            continue;
        }
        return Some(entry_phys - base);
    }
    None
}

fn select_kernel_entry(info: &crate::kernel::elf::Elf64Info, entry: u64) -> u64 {
    if entry != 0 {
        log::warn!("kernel entry: using e_entry=0x{:x}", entry);
        return entry;
    }
    if let Some(btext) = info.btext {
        log::warn!("kernel entry: using btext=0x{:x}", btext);
        return btext;
    }
    if let Some(btext) = info.section_addr(".btext") {
        log::warn!("kernel entry: using .btext=0x{:x}", btext);
        return btext;
    }
    if let Some(text) = info.section_addr(".text") {
        log::warn!("kernel entry: using .text=0x{:x}", text);
        return text;
    }
    entry
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

    fn alloc_copy_at(&mut self, offset: usize, data: &[u8]) -> Result<u64> {
        if data.is_empty() {
            return Err(BootError::InvalidData("staging alloc empty data"));
        }
        if offset > self.size {
            return Err(BootError::InvalidData("staging alloc offset out of range"));
        }
        let end = offset
            .checked_add(data.len())
            .ok_or(BootError::InvalidData("staging alloc overflow"))?;
        if end > self.size {
            return Err(BootError::InvalidData("staging alloc out of space"));
        }
        let dst = (self.base + offset as u64) as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        if end > self.cursor {
            self.cursor = end;
        }
        Ok(self.base + offset as u64)
    }
}

fn stage_kernel_and_modules(
    staging: &mut StagingArea,
    kernel: &LoadedKernelImagePhys,
    modules: &mut [crate::kernel::module::Module],
) -> Result<()> {
    let _staged_kernel = staging.alloc_copy_from_phys_at(0, kernel.base, kernel.size)?;
    staging.kernel_base = KERNEL_PHYS_BASE;
    for module in modules.iter_mut() {
        if let Some(src) = module.phys_addr {
            let staged = staging.alloc_copy_from_phys(src, module.data_len)?;
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

    fn alloc_copy_from_phys_at(&mut self, offset: usize, src: u64, size: usize) -> Result<u64> {
        if size == 0 {
            return Err(BootError::InvalidData("staging copy empty"));
        }
        if offset > self.size {
            return Err(BootError::InvalidData("staging copy offset out of range"));
        }
        let end = offset
            .checked_add(size)
            .ok_or(BootError::InvalidData("staging alloc overflow"))?;
        if end > self.size {
            return Err(BootError::InvalidData("staging alloc out of space"));
        }
        let dst = (self.base + offset as u64) as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src as *const u8, dst, size);
        }
        if end > self.cursor {
            self.cursor = end;
        }
        Ok(self.base + offset as u64)
    }
}
