extern crate alloc;

use alloc::vec::Vec;

use crate::error::{BootError, Result};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const EM_X86_64: u16 = 62;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;

const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_VERSION: usize = 6;

pub struct ElfLoader;

#[derive(Debug, Clone)]
pub struct Elf64Info {
    pub entry: u64,
    #[allow(dead_code)]
    pub preload_bootstrap: Option<u64>,
    pub btext: Option<u64>,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
}

#[derive(Debug, Clone)]
pub struct LoadedKernelImage {
    pub base: u64,
    pub entry: u64,
    pub image: Vec<u8>,
    pub info: Elf64Info,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: alloc::string::String,
    #[allow(dead_code)]
    pub index: usize,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub entsize: u64,
    #[allow(dead_code)]
    pub flags: u64,
    pub sh_type: u32,
    pub link: u32,
}

impl ElfLoader {
    pub fn parse_kernel(&self, image: &[u8]) -> Result<Elf64Info> {
        let header = parse_elf64_header(image)?;
        if header.e_machine != EM_X86_64 {
            return Err(BootError::Unsupported("unsupported ELF machine"));
        }
        if header.e_type != ET_EXEC && header.e_type != ET_DYN {
            return Err(BootError::Unsupported("unsupported ELF type"));
        }
        let phdrs = parse_program_headers(image, &header)?;
        let shdrs = parse_section_headers(image, &header)?;
        let preload_bootstrap = find_symbol_addr(image, &shdrs, "preload_bootstrap_relocate")
            .or_else(|| find_symbol_addr(image, &shdrs, "preload_bootstrap"));
        let btext = find_symbol_addr(image, &shdrs, "btext");
        Ok(Elf64Info {
            entry: header.e_entry,
            preload_bootstrap,
            btext,
            program_headers: phdrs,
            section_headers: shdrs,
        })
    }

    pub fn load_kernel_image(&self, image: &[u8]) -> Result<LoadedKernelImage> {
        let info = self.parse_kernel(image)?;
        let (start, end) = info
            .load_range()
            .ok_or(BootError::InvalidData("ELF has no loadable segments"))?;
        if end <= start {
            return Err(BootError::InvalidData("ELF load range invalid"));
        }
        let size = end
            .checked_sub(start)
            .ok_or(BootError::InvalidData("ELF load size overflow"))?;
        let size = usize::try_from(size)
            .map_err(|_| BootError::InvalidData("ELF load size too large"))?;
        let mut buf = alloc::vec![0u8; size];

        for phdr in &info.program_headers {
            if phdr.p_type != PT_LOAD {
                continue;
            }
            if phdr.filesz > phdr.memsz {
                return Err(BootError::InvalidData("ELF filesz exceeds memsz"));
            }
            let base = if phdr.paddr != 0 { phdr.paddr } else { phdr.vaddr };
            if base < start {
                return Err(BootError::InvalidData("ELF load address underflow"));
            }
            let dst_off = usize::try_from(base - start)
                .map_err(|_| BootError::InvalidData("ELF load offset overflow"))?;
            let filesz = usize::try_from(phdr.filesz)
                .map_err(|_| BootError::InvalidData("ELF filesz too large"))?;
            let memsz = usize::try_from(phdr.memsz)
                .map_err(|_| BootError::InvalidData("ELF memsz too large"))?;
            let src_off = usize::try_from(phdr.offset)
                .map_err(|_| BootError::InvalidData("ELF file offset too large"))?;
            let src_end = src_off
                .checked_add(filesz)
                .ok_or(BootError::InvalidData("ELF file offset overflow"))?;
            let dst_end = dst_off
                .checked_add(memsz)
                .ok_or(BootError::InvalidData("ELF load range overflow"))?;
            if src_end > image.len() || dst_end > buf.len() {
                return Err(BootError::InvalidData("ELF segment out of range"));
            }
            if filesz > 0 {
                buf[dst_off..dst_off + filesz].copy_from_slice(&image[src_off..src_end]);
            }
        }

        Ok(LoadedKernelImage {
            base: start,
            entry: info.entry,
            image: buf,
            info,
        })
    }
}

impl Elf64Info {
    pub fn symbol_addr(&self, image: &[u8], name: &str) -> Option<u64> {
        find_symbol_addr(image, &self.section_headers, name)
    }

    pub fn addr_to_offset(&self, base: u64, size: usize, addr: u64) -> Option<u64> {
        let end = base.checked_add(size as u64)?;
        for phdr in &self.program_headers {
            if phdr.p_type != PT_LOAD {
                continue;
            }
            let vbase = phdr.vaddr;
            let vend = vbase.saturating_add(phdr.memsz);
            if addr < vbase || addr >= vend {
                continue;
            }
            let pbase = if phdr.paddr != 0 { phdr.paddr } else { phdr.vaddr };
            let phys = pbase.saturating_add(addr.saturating_sub(vbase));
            if phys < base || phys >= end {
                continue;
            }
            return Some(phys - base);
        }
        None
    }

    pub fn load_range(&self) -> Option<(u64, u64)> {
        let mut min = u64::MAX;
        let mut max = 0u64;
        let mut found = false;
        for phdr in &self.program_headers {
            if phdr.p_type != PT_LOAD {
                continue;
            }
            let base = if phdr.paddr != 0 { phdr.paddr } else { phdr.vaddr };
            let end = base.saturating_add(phdr.memsz);
            if !found {
                min = base;
                max = end;
                found = true;
            } else {
                min = core::cmp::min(min, base);
                max = core::cmp::max(max, end);
            }
        }
        if found {
            Some((min, max))
        } else {
            None
        }
    }

    pub fn section_addr(&self, name: &str) -> Option<u64> {
        self.section_headers
            .iter()
            .find(|section| section.name == name)
            .map(|section| section.addr)
    }
}

struct Elf64Header {
    e_type: u16,
    e_machine: u16,
    e_entry: u64,
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
    e_shoff: u64,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

fn parse_elf64_header(image: &[u8]) -> Result<Elf64Header> {
    if image.len() < 64 {
        return Err(BootError::InvalidData("ELF header too short"));
    }
    if image[0..4] != ELF_MAGIC {
        return Err(BootError::InvalidData("ELF magic mismatch"));
    }
    if image[EI_CLASS] != ELFCLASS64 {
        return Err(BootError::InvalidData("ELF class is not 64-bit"));
    }
    if image[EI_DATA] != ELFDATA2LSB {
        return Err(BootError::InvalidData("ELF data encoding unsupported"));
    }
    if image[EI_VERSION] != EV_CURRENT {
        return Err(BootError::InvalidData("ELF version unsupported"));
    }

    let e_type = le_u16(image, 16)?;
    let e_machine = le_u16(image, 18)?;
    let e_entry = le_u64(image, 24)?;
    let e_phoff = le_u64(image, 32)?;
    let e_shoff = le_u64(image, 40)?;
    let e_phentsize = le_u16(image, 54)?;
    let e_phnum = le_u16(image, 56)?;
    let e_shentsize = le_u16(image, 58)?;
    let e_shnum = le_u16(image, 60)?;
    let e_shstrndx = le_u16(image, 62)?;

    if e_phentsize < 56 {
        return Err(BootError::InvalidData("ELF program header too small"));
    }

    Ok(Elf64Header {
        e_type,
        e_machine,
        e_entry,
        e_phoff,
        e_phentsize,
        e_phnum,
        e_shoff,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    })
}

fn parse_program_headers(image: &[u8], header: &Elf64Header) -> Result<Vec<ProgramHeader>> {
    let phoff = usize::try_from(header.e_phoff)
        .map_err(|_| BootError::InvalidData("ELF phoff overflow"))?;
    let entsize = usize::from(header.e_phentsize);
    let count = usize::from(header.e_phnum);
    let size = entsize
        .checked_mul(count)
        .ok_or(BootError::InvalidData("ELF program header size overflow"))?;
    let end = phoff
        .checked_add(size)
        .ok_or(BootError::InvalidData("ELF program header end overflow"))?;
    if end > image.len() {
        return Err(BootError::InvalidData("ELF program headers out of range"));
    }

    let mut headers = Vec::with_capacity(count);
    for idx in 0..count {
        let offset = phoff + idx * entsize;
        let buf = &image[offset..offset + entsize];
        headers.push(parse_program_header(buf)?);
    }
    Ok(headers)
}

fn parse_program_header(buf: &[u8]) -> Result<ProgramHeader> {
    if buf.len() < 56 {
        return Err(BootError::InvalidData("ELF program header too short"));
    }
    Ok(ProgramHeader {
        p_type: le_u32(buf, 0)?,
        flags: le_u32(buf, 4)?,
        offset: le_u64(buf, 8)?,
        vaddr: le_u64(buf, 16)?,
        paddr: le_u64(buf, 24)?,
        filesz: le_u64(buf, 32)?,
        memsz: le_u64(buf, 40)?,
        align: le_u64(buf, 48)?,
    })
}

#[derive(Debug, Clone)]
struct RawSectionHeader {
    name_offset: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

fn parse_section_headers(image: &[u8], header: &Elf64Header) -> Result<Vec<SectionHeader>> {
    if header.e_shnum == 0 || header.e_shentsize < 64 {
        return Ok(Vec::new());
    }
    let shoff = usize::try_from(header.e_shoff)
        .map_err(|_| BootError::InvalidData("ELF shoff overflow"))?;
    let entsize = usize::from(header.e_shentsize);
    let count = usize::from(header.e_shnum);
    let size = entsize
        .checked_mul(count)
        .ok_or(BootError::InvalidData("ELF section header size overflow"))?;
    let end = shoff
        .checked_add(size)
        .ok_or(BootError::InvalidData("ELF section header end overflow"))?;
    if end > image.len() {
        return Err(BootError::InvalidData("ELF section headers out of range"));
    }

    let mut raw = Vec::with_capacity(count);
    for idx in 0..count {
        let offset = shoff + idx * entsize;
        let buf = &image[offset..offset + entsize];
        raw.push(parse_section_header(buf)?);
    }

    let shstr_index = usize::from(header.e_shstrndx);
    let shstr = if shstr_index < raw.len() {
        let sh = &raw[shstr_index];
        let start = usize::try_from(sh.offset)
            .map_err(|_| BootError::InvalidData("ELF shstrtab offset overflow"))?;
        let end = start
            .checked_add(usize::try_from(sh.size).map_err(|_| BootError::InvalidData("ELF shstrtab size overflow"))?)
            .ok_or(BootError::InvalidData("ELF shstrtab end overflow"))?;
        if end <= image.len() {
            &image[start..end]
        } else {
            &[]
        }
    } else {
        &[]
    };

    let mut sections = Vec::with_capacity(raw.len());
    for (idx, sh) in raw.into_iter().enumerate() {
        let name = read_shstr(shstr, sh.name_offset);
        sections.push(SectionHeader {
            name,
            index: idx,
            addr: sh.addr,
            offset: sh.offset,
            size: sh.size,
            entsize: sh.entsize,
            flags: sh.flags,
            sh_type: sh.sh_type,
            link: sh.link,
        });
    }

    Ok(sections)
}

fn parse_section_header(buf: &[u8]) -> Result<RawSectionHeader> {
    if buf.len() < 64 {
        return Err(BootError::InvalidData("ELF section header too short"));
    }
    Ok(RawSectionHeader {
        name_offset: le_u32(buf, 0)?,
        sh_type: le_u32(buf, 4)?,
        flags: le_u64(buf, 8)?,
        addr: le_u64(buf, 16)?,
        offset: le_u64(buf, 24)?,
        size: le_u64(buf, 32)?,
        link: le_u32(buf, 40)?,
        entsize: le_u64(buf, 56)?,
    })
}

fn read_shstr(shstr: &[u8], offset: u32) -> alloc::string::String {
    let start = offset as usize;
    if start >= shstr.len() {
        return alloc::string::String::new();
    }
    let mut end = start;
    while end < shstr.len() && shstr[end] != 0 {
        end += 1;
    }
    alloc::string::String::from_utf8_lossy(&shstr[start..end]).into_owned()
}

fn find_symbol_addr(image: &[u8], sections: &[SectionHeader], name: &str) -> Option<u64> {
    const SHT_SYMTAB: u32 = 2;
    const SHT_STRTAB: u32 = 3;
    const SYM_ENTRY_SIZE: u64 = 24;

    let name_bytes = name.as_bytes();
    for section in sections {
        if section.sh_type != SHT_SYMTAB {
            continue;
        }
        let entsize = if section.entsize == 0 {
            SYM_ENTRY_SIZE
        } else {
            section.entsize
        };
        if entsize < SYM_ENTRY_SIZE {
            continue;
        }
        let link = section.link as usize;
        if link >= sections.len() {
            continue;
        }
        let strtab = &sections[link];
        if strtab.sh_type != SHT_STRTAB {
            continue;
        }
        let symtab = slice_by_offset(image, section.offset, section.size)?;
        let strtab_bytes = slice_by_offset(image, strtab.offset, strtab.size)?;

        let mut off = 0u64;
        while off + entsize <= section.size {
            let entry = &symtab[off as usize..(off + entsize) as usize];
            let name_off = le_u32(entry, 0).ok()?;
            if strtab_eq(strtab_bytes, name_off, name_bytes) {
                return le_u64(entry, 8).ok();
            }
            off = off.saturating_add(entsize);
        }
    }
    None
}

fn slice_by_offset(image: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let size = usize::try_from(size).ok()?;
    let end = start.checked_add(size)?;
    if end > image.len() {
        return None;
    }
    Some(&image[start..end])
}

fn strtab_eq(strtab: &[u8], offset: u32, name: &[u8]) -> bool {
    let start = offset as usize;
    if start >= strtab.len() {
        return false;
    }
    let mut idx = 0usize;
    let mut pos = start;
    while pos < strtab.len() && strtab[pos] != 0 {
        if idx >= name.len() || strtab[pos] != name[idx] {
            return false;
        }
        idx += 1;
        pos += 1;
    }
    idx == name.len()
}

fn le_u16(buf: &[u8], offset: usize) -> Result<u16> {
    if buf.len() < offset + 2 {
        return Err(BootError::InvalidData("ELF u16 out of range"));
    }
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

fn le_u32(buf: &[u8], offset: usize) -> Result<u32> {
    if buf.len() < offset + 4 {
        return Err(BootError::InvalidData("ELF u32 out of range"));
    }
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

fn le_u64(buf: &[u8], offset: usize) -> Result<u64> {
    if buf.len() < offset + 8 {
        return Err(BootError::InvalidData("ELF u64 out of range"));
    }
    Ok(u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]))
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::vec::Vec;
    use super::{ElfLoader, ELFCLASS64, ELFDATA2LSB, ELF_MAGIC, EV_CURRENT};

    fn decode_hex(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut high: Option<u8> = None;
        for byte in text.bytes() {
            let val = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => continue,
            };
            if let Some(high) = high.take() {
                out.push((high << 4) | val);
            } else {
                high = Some(val);
            }
        }
        assert!(high.is_none(), "odd number of hex digits");
        out
    }

    #[test]
    fn test_parse_elf64_header_and_phdr() {
        let mut image = alloc::vec![0u8; 64 + 56];
        image[0..4].copy_from_slice(&ELF_MAGIC);
        image[4] = ELFCLASS64;
        image[5] = ELFDATA2LSB;
        image[6] = EV_CURRENT;
        image[16..18].copy_from_slice(&2u16.to_le_bytes());
        image[18..20].copy_from_slice(&62u16.to_le_bytes());
        image[24..32].copy_from_slice(&0x100000u64.to_le_bytes());
        image[32..40].copy_from_slice(&(64u64).to_le_bytes());
        image[54..56].copy_from_slice(&(56u16).to_le_bytes());
        image[56..58].copy_from_slice(&(1u16).to_le_bytes());

        let phdr = 64;
        image[phdr..phdr + 4].copy_from_slice(&1u32.to_le_bytes());
        image[phdr + 4..phdr + 8].copy_from_slice(&5u32.to_le_bytes());
        image[phdr + 8..phdr + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        image[phdr + 16..phdr + 24].copy_from_slice(&0x100000u64.to_le_bytes());
        image[phdr + 24..phdr + 32].copy_from_slice(&0x100000u64.to_le_bytes());
        image[phdr + 32..phdr + 40].copy_from_slice(&0x2000u64.to_le_bytes());
        image[phdr + 40..phdr + 48].copy_from_slice(&0x3000u64.to_le_bytes());
        image[phdr + 48..phdr + 56].copy_from_slice(&0x200000u64.to_le_bytes());

        let loader = ElfLoader;
        let info = loader.parse_kernel(&image).expect("parse");
        assert_eq!(info.entry, 0x100000);
        assert_eq!(info.program_headers.len(), 1);
        assert_eq!(info.program_headers[0].offset, 0x1000);
        let range = info.load_range().expect("range");
        assert_eq!(range.0, 0x100000);
        assert_eq!(range.1, 0x103000);
    }

    #[test]
    fn test_load_kernel_image_segments() {
        let mut image = alloc::vec![0u8; 0x90];
        image[0..4].copy_from_slice(&ELF_MAGIC);
        image[4] = ELFCLASS64;
        image[5] = ELFDATA2LSB;
        image[6] = EV_CURRENT;
        image[16..18].copy_from_slice(&2u16.to_le_bytes());
        image[18..20].copy_from_slice(&62u16.to_le_bytes());
        image[24..32].copy_from_slice(&0x200000u64.to_le_bytes());
        image[32..40].copy_from_slice(&(64u64).to_le_bytes());
        image[54..56].copy_from_slice(&(56u16).to_le_bytes());
        image[56..58].copy_from_slice(&(1u16).to_le_bytes());

        let phdr = 64;
        image[phdr..phdr + 4].copy_from_slice(&1u32.to_le_bytes());
        image[phdr + 4..phdr + 8].copy_from_slice(&5u32.to_le_bytes());
        image[phdr + 8..phdr + 16].copy_from_slice(&0x80u64.to_le_bytes());
        image[phdr + 16..phdr + 24].copy_from_slice(&0x200000u64.to_le_bytes());
        image[phdr + 24..phdr + 32].copy_from_slice(&0u64.to_le_bytes());
        image[phdr + 32..phdr + 40].copy_from_slice(&4u64.to_le_bytes());
        image[phdr + 40..phdr + 48].copy_from_slice(&8u64.to_le_bytes());
        image[phdr + 48..phdr + 56].copy_from_slice(&0x1000u64.to_le_bytes());

        image[0x80..0x84].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let loader = ElfLoader;
        let loaded = loader.load_kernel_image(&image).expect("load");
        assert_eq!(loaded.base, 0x200000);
        assert_eq!(loaded.entry, 0x200000);
        assert_eq!(loaded.image.len(), 8);
        assert_eq!(&loaded.image[0..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(&loaded.image[4..8], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_fixture_single_segment() {
        let fixture = include_str!("fixtures/elf64-single.hex");
        let image = decode_hex(fixture);
        let loader = ElfLoader;
        let loaded = loader.load_kernel_image(&image).expect("load");
        assert_eq!(loaded.base, 0x200000);
        assert_eq!(loaded.entry, 0x200000);
        assert_eq!(loaded.image.len(), 8);
        assert_eq!(&loaded.image[0..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(&loaded.image[4..8], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_fixture_two_segments() {
        let fixture = include_str!("fixtures/elf64-two-seg.hex");
        let image = decode_hex(fixture);
        let loader = ElfLoader;
        let loaded = loader.load_kernel_image(&image).expect("load");
        assert_eq!(loaded.base, 0x400000);
        assert_eq!(loaded.entry, 0x400000);
        assert_eq!(loaded.image.len(), 0x1008);
        assert_eq!(&loaded.image[0..4], &[0x11, 0x22, 0x33, 0x44]);
        assert!(loaded.image[4..0x1000].iter().all(|&b| b == 0));
        assert_eq!(&loaded.image[0x1000..0x1004], &[0x55, 0x66, 0x77, 0x88]);
        assert_eq!(&loaded.image[0x1004..0x1008], &[0, 0, 0, 0]);
    }
}
