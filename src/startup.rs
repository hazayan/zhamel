extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::boot::{self, SearchType};
use uefi::runtime::{self, VariableVendor};
use uefi::table::cfg::ConfigTableEntry;
use uefi::CStr16;
use uefi::proto::console::gop::GraphicsOutput;
use uefi::Identify;
use uefi::system;

use crate::env::loader::LoaderEnv;

pub fn init(loader_env: &mut LoaderEnv) {
    let acpi = detect_acpi(loader_env);
    detect_smbios(loader_env);
    let conout_serial = conout_has_serial().unwrap_or(false);
    let gop_present = has_gop();
    log::info!("uefi: gop present={}", gop_present);
    loader_env.set("zhamel.gop_present", if gop_present { "1" } else { "0" });
    let trial_val = loader_env.get("zhamel_trial");
    if trial_val.is_none() && !gop_present {
        loader_env.set("zhamel_trial", "1");
        log::warn!("zhamel_trial defaulted to 1 (no GOP detected)");
    }
    let trial = matches!(
        loader_env.get("zhamel_trial"),
        Some("1") | Some("YES") | Some("yes") | Some("true")
    );
    if trial && (acpi.no_vga || !gop_present) {
        // Ensure a hinted vga0 exists so the disabled hint is applied
        // before any probe runs.
        loader_env.set_if_unset("hint.vga.0.at", "isa");
        loader_env.set_if_unset("hint.vga.0.disabled", "1");
        log::warn!(
            "vga: disabling hint.vga.0 (acpi_no_vga={}, gop_present={})",
            acpi.no_vga,
            gop_present
        );
    }
    select_console(loader_env, acpi.serial_present || conout_serial, gop_present);
}

struct AcpiInfo {
    serial_present: bool,
    no_vga: bool,
}

fn detect_acpi(loader_env: &mut LoaderEnv) -> AcpiInfo {
    let mut acpi_addr = None;
    system::with_config_table(|tables| {
        for entry in tables {
            if entry.guid == ConfigTableEntry::ACPI2_GUID {
                acpi_addr = Some(entry.address);
                break;
            }
        }
        if acpi_addr.is_none() {
            for entry in tables {
                if entry.guid == ConfigTableEntry::ACPI_GUID {
                    acpi_addr = Some(entry.address);
                    break;
                }
            }
        }
    });

    let Some(addr) = acpi_addr else {
        return AcpiInfo {
            serial_present: false,
            no_vga: false,
        };
    };

    let rsdp = match unsafe { Rsdp::from_ptr(addr.cast()) } {
        Some(rsdp) => rsdp,
        None => {
            return AcpiInfo {
                serial_present: false,
                no_vga: false,
            }
        }
    };

    loader_env.set("acpi.rsdp", &format!("0x{:016x}", rsdp.address));
    loader_env.set("acpi.revision", &rsdp.revision.to_string());
    loader_env.set("acpi.oem", &rsdp.oem_id);
    loader_env.set("acpi.rsdt", &format!("0x{:016x}", rsdp.rsdt_address as u64));
    if let Some(xsdt) = rsdp.xsdt_address {
        loader_env.set("acpi.xsdt", &format!("0x{:016x}", xsdt));
    }
    if let Some(length) = rsdp.xsdt_length {
        loader_env.set("acpi.xsdt_length", &length.to_string());
    }

    let spcr = find_acpi_table(&rsdp, *b"SPCR");
    let serial_present = spcr
        .and_then(|ptr| unsafe { read_spcr(ptr) })
        .map(|spcr| spcr.serial_port_address != 0)
        .unwrap_or(false);

    let no_vga = find_acpi_table(&rsdp, *b"FACP")
        .and_then(|ptr| unsafe { read_fadt_boot_flags(ptr) })
        .map(|flags| (flags & ACPI_FADT_NO_VGA) != 0)
        .unwrap_or(false);

    AcpiInfo {
        serial_present,
        no_vga,
    }
}

fn detect_smbios(loader_env: &mut LoaderEnv) {
    let mut smbios_addr = None;
    system::with_config_table(|tables| {
        for entry in tables {
            if entry.guid == ConfigTableEntry::SMBIOS3_GUID {
                smbios_addr = Some(entry.address);
                return;
            }
        }
        for entry in tables {
            if entry.guid == ConfigTableEntry::SMBIOS_GUID {
                smbios_addr = Some(entry.address);
                return;
            }
        }
    });

    if let Some(addr) = smbios_addr {
        loader_env.set("hint.smbios.0.mem", &format!("0x{:016x}", addr as u64));
    }
}

fn select_console(loader_env: &mut LoaderEnv, serial_present: bool, gop_present: bool) {
    let trial = matches!(
        loader_env.get("zhamel_trial"),
        Some("1") | Some("YES") | Some("yes") | Some("true")
    );
    loader_env.set_if_unset("console", "efi");

    let console = loader_env.get("console").unwrap_or("efi");
    if !gop_present && console == "efi" {
        let console_value = if trial { "comconsole" } else { "efi,comconsole" };
        loader_env.set("console", console_value);
        let howto = if console_value == "comconsole" {
            RB_SERIAL
        } else {
            RB_SERIAL | RB_MULTIPLE
        };
        loader_env.set("boot_howto", &howto.to_string());
        if trial {
            ensure_serial_hints(loader_env);
        }
        return;
    }
    if serial_present && console == "efi" {
        loader_env.set("console", "efi,comconsole");
        let howto = RB_SERIAL | RB_MULTIPLE;
        loader_env.set("boot_howto", &howto.to_string());
        if trial {
            ensure_serial_hints(loader_env);
        }
        return;
    }
    let console = loader_env
        .get("console")
        .unwrap_or("efi")
        .to_string();
    if console.contains("comconsole") {
        if trial {
            ensure_serial_hints(loader_env);
        }
        if loader_env.get("boot_howto").is_none() {
            let howto = if console.contains("efi") {
                RB_SERIAL | RB_MULTIPLE
            } else {
                RB_SERIAL
            };
            loader_env.set("boot_howto", &howto.to_string());
            return;
        }
    }
    if loader_env.get("boot_howto").is_none() {
        loader_env.set("boot_howto", "0");
    }
}

fn ensure_serial_hints(loader_env: &mut LoaderEnv) {
    loader_env.set_if_unset("hw.uart.console", "io:1016,br:115200");
    loader_env.set_if_unset("hint.uart.0.at", "isa");
    loader_env.set_if_unset("hint.uart.0.port", "0x3f8");
    loader_env.set_if_unset("hint.uart.0.irq", "4");
    loader_env.set_if_unset("hint.uart.0.flags", "0x10");
    loader_env.set_if_unset("hint.uart.0.baud", "115200");
}

const RB_SERIAL: u32 = 0x1000;
const RB_MULTIPLE: u32 = 0x20000000;

#[repr(C, packed)]
struct RsdpV1 {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

#[repr(C, packed)]
struct RsdpV2 {
    v1: RsdpV1,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    _reserved: [u8; 3],
}

struct Rsdp {
    address: u64,
    revision: u8,
    oem_id: String,
    rsdt_address: u32,
    xsdt_address: Option<u64>,
    xsdt_length: Option<u32>,
}

impl Rsdp {
    unsafe fn from_ptr(ptr: *const u8) -> Option<Self> {
        let v1 = unsafe { ptr.cast::<RsdpV1>().read_unaligned() };
        if &v1.signature != b"RSD PTR " {
            return None;
        }
        let revision = if v1.revision == 0 { 1 } else { v1.revision };
        let oem_id = String::from_utf8_lossy(&v1.oem_id).trim().to_string();
        let mut info = Rsdp {
            address: ptr as u64,
            revision,
            oem_id,
            rsdt_address: v1.rsdt_address,
            xsdt_address: None,
            xsdt_length: None,
        };
        if v1.revision >= 2 {
            let v2 = unsafe { ptr.cast::<RsdpV2>().read_unaligned() };
            info.xsdt_address = Some(v2.xsdt_address);
            info.xsdt_length = Some(v2.length);
        }
        Some(info)
    }
}

#[repr(C, packed)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    _revision: u8,
    _checksum: u8,
    _oem_id: [u8; 6],
    _oem_table_id: [u8; 8],
    _oem_revision: u32,
    _creator_id: u32,
    _creator_revision: u32,
}

fn find_acpi_table(rsdp: &Rsdp, signature: [u8; 4]) -> Option<*const SdtHeader> {
    if let Some(xsdt_addr) = rsdp.xsdt_address {
        return find_acpi_table_xsdt(xsdt_addr, signature);
    }
    find_acpi_table_rsdt(rsdp.rsdt_address as u64, signature)
}

fn find_acpi_table_xsdt(xsdt_addr: u64, signature: [u8; 4]) -> Option<*const SdtHeader> {
    if xsdt_addr == 0 {
        return None;
    }
    let header = unsafe { (xsdt_addr as *const SdtHeader).read_unaligned() };
    let entries_len = header.length as usize - core::mem::size_of::<SdtHeader>();
    let entry_count = entries_len / core::mem::size_of::<u64>();
    let base = (xsdt_addr as *const u8).wrapping_add(core::mem::size_of::<SdtHeader>());
    for idx in 0..entry_count {
        let addr = unsafe { base.add(idx * 8).cast::<u64>().read_unaligned() };
        if addr == 0 {
            continue;
        }
        let sdt = unsafe { (addr as *const SdtHeader).read_unaligned() };
        if sdt.signature == signature {
            return Some(addr as *const SdtHeader);
        }
    }
    None
}

fn find_acpi_table_rsdt(rsdt_addr: u64, signature: [u8; 4]) -> Option<*const SdtHeader> {
    if rsdt_addr == 0 {
        return None;
    }
    let header = unsafe { (rsdt_addr as *const SdtHeader).read_unaligned() };
    let entries_len = header.length as usize - core::mem::size_of::<SdtHeader>();
    let entry_count = entries_len / core::mem::size_of::<u32>();
    let base = (rsdt_addr as *const u8).wrapping_add(core::mem::size_of::<SdtHeader>());
    for idx in 0..entry_count {
        let addr = unsafe { base.add(idx * 4).cast::<u32>().read_unaligned() } as u64;
        if addr == 0 {
            continue;
        }
        let sdt = unsafe { (addr as *const SdtHeader).read_unaligned() };
        if sdt.signature == signature {
            return Some(addr as *const SdtHeader);
        }
    }
    None
}

#[repr(C, packed)]
struct GenericAddress {
    _space_id: u8,
    _bit_width: u8,
    _bit_offset: u8,
    _access_width: u8,
    address: u64,
}

struct SpcrInfo {
    serial_port_address: u64,
}

unsafe fn read_spcr(ptr: *const SdtHeader) -> Option<SpcrInfo> {
    if ptr.is_null() {
        return None;
    }
    let header = unsafe { ptr.read_unaligned() };
    if header.length < core::mem::size_of::<SdtHeader>() as u32 + core::mem::size_of::<GenericAddress>() as u32 {
        return None;
    }
    let serial_offset = core::mem::size_of::<SdtHeader>() + 4;
    let serial_ptr = unsafe { (ptr as *const u8).add(serial_offset).cast::<GenericAddress>() };
    let serial = unsafe { serial_ptr.read_unaligned() };
    Some(SpcrInfo {
        serial_port_address: serial.address,
    })
}

const FADT_BOOTFLAGS_OFFSET: usize = 109;
const ACPI_FADT_NO_VGA: u16 = 1 << 2;

unsafe fn read_fadt_boot_flags(ptr: *const SdtHeader) -> Option<u16> {
    if ptr.is_null() {
        return None;
    }
    let header = unsafe { ptr.read_unaligned() };
    if (header.length as usize) < FADT_BOOTFLAGS_OFFSET + 2 {
        return None;
    }
    let base = ptr as *const u8;
    let flags_ptr = unsafe { base.add(FADT_BOOTFLAGS_OFFSET).cast::<u16>() };
    Some(u16::from_le(unsafe { flags_ptr.read_unaligned() }))
}

fn has_gop() -> bool {
    match boot::locate_handle_buffer(SearchType::ByProtocol(&GraphicsOutput::GUID)) {
        Ok(handles) => !handles.is_empty(),
        Err(_) => false,
    }
}

fn conout_has_serial() -> Option<bool> {
    let data = read_global_device_path("ConOut")?;
    Some(device_path_has_serial(&data))
}

fn read_global_device_path(name: &str) -> Option<Vec<u8>> {
    let mut buf = [0u16; 16];
    let name = CStr16::from_str_with_buf(name, &mut buf).ok()?;
    let (data, _attrs) = runtime::get_variable_boxed(name, &VariableVendor::GLOBAL_VARIABLE).ok()?;
    Some(data.into_vec())
}

fn device_path_has_serial(bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let ty = bytes[offset];
        let subtype = bytes[offset + 1];
        let len = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if len < 4 || offset + len > bytes.len() {
            break;
        }
        if ty == 0x02 && (subtype == 0x01 || subtype == 0x02) && len >= 12 {
            let hid = u32::from_le_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
            if (hid & 0xFFFF) == 0x0501 {
                return true;
            }
        }
        offset += len;
    }
    false
}
