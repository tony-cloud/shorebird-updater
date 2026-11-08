//! Measurement of the native module that contains the updater (the engine
//! library it is statically linked into): hardening stage P3, contract
//! `docs/HARDENING_CONTRACTS.md` §9 in the workspace.
//!
//! A measurement is `sha256:` over a domain-separated list of *regions*: the
//! immutable, loader-unmodified parts of the module. Regions are chosen so the
//! same value results from the engine artifact flutter_tools packages and
//! from the module the process actually loaded, across the platform
//! transformations that legitimately happen in between:
//!
//! - ELF (Android, Linux): every `PT_LOAD` segment without `PF_W`, its file
//!   bytes. Position-independent shared objects on these targets carry no text
//!   relocations, so these bytes are identical in memory. Runtime: the module
//!   containing this code, from `dl_iterate_phdr` (the loader's own program
//!   headers), hashed in memory.
//! - Mach-O (iOS, macOS): every non-zero-fill section of every segment whose
//!   initial protection is not writable, except `__LINKEDIT`. Code signing
//!   rewrites only load commands and `__LINKEDIT`, App Store encryption is
//!   undone in memory, and dyld fixups target writable segments only.
//!   Runtime: the image containing this code, from `dladdr`, hashed in memory.
//! - PE (Windows): the raw data of every section without
//!   `IMAGE_SCN_MEM_WRITE`. Authenticode changes only the header checksum,
//!   the certificate directory entry and appended data. Base relocations
//!   change `.rdata` in memory, so Windows measures the file of the loaded
//!   module (`GetModuleHandleExW` + `GetModuleFileNameW`), read once.
//!
//! Each region contributes a 32-byte label (Mach-O `segname`+`sectname`, PE
//! section name, zero for ELF), its virtual address and size as little-endian
//! u64, then its bytes. flutter_tools (`shorebird_build_manifest.dart`)
//! implements the same file-based rules; both are pinned to shared golden
//! values.
use sha2::{Digest, Sha256};

/// Domain separation for module measurements, version 1.
pub const MEASUREMENT_DOMAIN: &[u8] = b"open-shorebird.module-measurement.v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleFormat {
    Elf32,
    Elf64,
    MachO64,
    Pe,
}

impl ModuleFormat {
    fn tag(self) -> &'static [u8] {
        match self {
            ModuleFormat::Elf32 => b"elf32\0",
            ModuleFormat::Elf64 => b"elf64\0",
            ModuleFormat::MachO64 => b"macho64\0",
            ModuleFormat::Pe => b"pe\0",
        }
    }
}

/// Incremental measurement over regions in a fixed order.
pub struct Measurer {
    hasher: Sha256,
    regions: usize,
}

impl Measurer {
    pub fn new(format: ModuleFormat) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(MEASUREMENT_DOMAIN);
        hasher.update(format.tag());
        Measurer { hasher, regions: 0 }
    }

    pub fn region(&mut self, label: &[u8], address: u64, bytes: &[u8]) {
        let mut padded = [0u8; 32];
        let n = label.len().min(32);
        padded[..n].copy_from_slice(&label[..n]);
        self.hasher.update(padded);
        self.hasher.update(address.to_le_bytes());
        self.hasher.update((bytes.len() as u64).to_le_bytes());
        self.hasher.update(bytes);
        self.regions += 1;
    }

    /// `sha256:<hex>`; a module with no measurable region is an error.
    pub fn finish(self) -> Result<String, MeasureError> {
        if self.regions == 0 {
            return Err(MeasureError::NoRegions);
        }
        Ok(format!("sha256:{}", hex::encode(self.hasher.finalize())))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeasureError {
    /// Not a supported little-endian ELF, thin 64-bit Mach-O or PE image.
    UnsupportedFormat,
    /// A header, table or region lies outside the image.
    Truncated,
    NoRegions,
    /// The running module could not be located or read.
    Unavailable(String),
}

impl std::fmt::Display for MeasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasureError::UnsupportedFormat => write!(f, "unsupported module format"),
            MeasureError::Truncated => write!(f, "module image is truncated"),
            MeasureError::NoRegions => write!(f, "module has no measurable region"),
            MeasureError::Unavailable(why) => write!(f, "running module unavailable: {why}"),
        }
    }
}

fn slice(bytes: &[u8], offset: u64, len: u64) -> Result<&[u8], MeasureError> {
    let start = usize::try_from(offset).map_err(|_| MeasureError::Truncated)?;
    let len = usize::try_from(len).map_err(|_| MeasureError::Truncated)?;
    let end = start.checked_add(len).ok_or(MeasureError::Truncated)?;
    bytes.get(start..end).ok_or(MeasureError::Truncated)
}

fn u16_at(bytes: &[u8], offset: u64) -> Result<u16, MeasureError> {
    Ok(u16::from_le_bytes(
        slice(bytes, offset, 2)?.try_into().unwrap(),
    ))
}

fn u32_at(bytes: &[u8], offset: u64) -> Result<u32, MeasureError> {
    Ok(u32::from_le_bytes(
        slice(bytes, offset, 4)?.try_into().unwrap(),
    ))
}

fn u64_at(bytes: &[u8], offset: u64) -> Result<u64, MeasureError> {
    Ok(u64::from_le_bytes(
        slice(bytes, offset, 8)?.try_into().unwrap(),
    ))
}

const PT_LOAD: u32 = 1;
const PF_W: u32 = 2;

/// An ELF program header, reduced to the fields a measurement uses.
#[derive(Clone, Copy, Debug)]
pub struct ElfSegment {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
}

impl ElfSegment {
    pub fn is_measured(&self) -> bool {
        self.p_type == PT_LOAD && self.p_flags & PF_W == 0 && self.p_filesz > 0
    }
}

/// Measures an ELF file image (`ET_DYN`/`ET_EXEC`, little-endian).
pub fn measure_elf_file(image: &[u8]) -> Result<String, MeasureError> {
    if image.len() < 0x34 || &image[..4] != b"\x7fELF" || image[5] != 1 {
        return Err(MeasureError::UnsupportedFormat);
    }
    let (format, phoff, phentsize, phnum) = match image[4] {
        1 => (
            ModuleFormat::Elf32,
            u64::from(u32_at(image, 0x1c)?),
            u16_at(image, 0x2a)?,
            u16_at(image, 0x2c)?,
        ),
        2 => (
            ModuleFormat::Elf64,
            u64_at(image, 0x20)?,
            u16_at(image, 0x36)?,
            u16_at(image, 0x38)?,
        ),
        _ => return Err(MeasureError::UnsupportedFormat),
    };
    let expected_entsize = if format == ModuleFormat::Elf32 {
        32
    } else {
        56
    };
    // PN_XNUM (0xffff) moves the count into a section header; never emitted
    // for shared objects, so it is refused rather than supported.
    if phentsize != expected_entsize || phnum == 0xffff {
        return Err(MeasureError::UnsupportedFormat);
    }
    let mut segments = Vec::with_capacity(phnum.into());
    for index in 0..u64::from(phnum) {
        let at = phoff
            .checked_add(index * u64::from(phentsize))
            .ok_or(MeasureError::Truncated)?;
        segments.push(if format == ModuleFormat::Elf32 {
            ElfSegment {
                p_type: u32_at(image, at)?,
                p_offset: u64::from(u32_at(image, at + 4)?),
                p_vaddr: u64::from(u32_at(image, at + 8)?),
                p_filesz: u64::from(u32_at(image, at + 16)?),
                p_flags: u32_at(image, at + 24)?,
            }
        } else {
            ElfSegment {
                p_type: u32_at(image, at)?,
                p_flags: u32_at(image, at + 4)?,
                p_offset: u64_at(image, at + 8)?,
                p_vaddr: u64_at(image, at + 16)?,
                p_filesz: u64_at(image, at + 32)?,
            }
        });
    }
    let mut measurer = Measurer::new(format);
    for segment in segments.iter().filter(|s| s.is_measured()) {
        measurer.region(
            &[],
            segment.p_vaddr,
            slice(image, segment.p_offset, segment.p_filesz)?,
        );
    }
    measurer.finish()
}

const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_SEGMENT_64: u32 = 0x19;
const VM_PROT_WRITE: u32 = 2;
const SECTION_TYPE_MASK: u32 = 0xff;
const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;

/// A Mach-O section selected for measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachOSection {
    pub label: [u8; 32],
    pub addr: u64,
    pub size: u64,
    pub file_offset: u64,
}

/// Mach-O header facts a measurement needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachOLayout {
    pub cputype: u32,
    /// `vmaddr` of the segment mapped from file offset 0 (`__TEXT`).
    pub text_vmaddr: u64,
    pub sections: Vec<MachOSection>,
}

/// Parses the load commands of a thin 64-bit Mach-O image. `image` may be a
/// whole file or, at run time, the mapped header and load commands.
pub fn parse_macho(image: &[u8]) -> Result<MachOLayout, MeasureError> {
    if image.len() < 32 || u32_at(image, 0)? != MH_MAGIC_64 {
        return Err(MeasureError::UnsupportedFormat);
    }
    let cputype = u32_at(image, 4)?;
    let ncmds = u32_at(image, 16)?;
    let sizeofcmds = u64::from(u32_at(image, 20)?);
    let end = 32u64
        .checked_add(sizeofcmds)
        .ok_or(MeasureError::Truncated)?;
    slice(image, 32, sizeofcmds)?;
    let mut at = 32u64;
    let mut text_vmaddr = None;
    let mut sections = Vec::new();
    for _ in 0..ncmds {
        let cmd = u32_at(image, at)?;
        let cmdsize = u64::from(u32_at(image, at + 4)?);
        if cmdsize < 8 || at + cmdsize > end {
            return Err(MeasureError::Truncated);
        }
        if cmd == LC_SEGMENT_64 {
            if cmdsize < 72 {
                return Err(MeasureError::Truncated);
            }
            let segname: [u8; 16] = slice(image, at + 8, 16)?.try_into().unwrap();
            let vmaddr = u64_at(image, at + 24)?;
            let fileoff = u64_at(image, at + 40)?;
            let filesize = u64_at(image, at + 48)?;
            let initprot = u32_at(image, at + 60)?;
            let nsects = u64::from(u32_at(image, at + 64)?);
            if 72 + nsects * 80 > cmdsize {
                return Err(MeasureError::Truncated);
            }
            if fileoff == 0 && filesize > 0 && text_vmaddr.is_none() {
                text_vmaddr = Some(vmaddr);
            }
            let measured = initprot & VM_PROT_WRITE == 0 && &segname[..11] != b"__LINKEDIT\0";
            for index in 0..nsects {
                let s = at + 72 + index * 80;
                let flags = u32_at(image, s + 64)?;
                let kind = flags & SECTION_TYPE_MASK;
                let size = u64_at(image, s + 40)?;
                if !measured
                    || size == 0
                    || kind == S_ZEROFILL
                    || kind == S_GB_ZEROFILL
                    || kind == S_THREAD_LOCAL_ZEROFILL
                {
                    continue;
                }
                let mut label = [0u8; 32];
                label[..16].copy_from_slice(&segname);
                label[16..].copy_from_slice(slice(image, s, 16)?);
                sections.push(MachOSection {
                    label,
                    addr: u64_at(image, s + 32)?,
                    size,
                    file_offset: u64::from(u32_at(image, s + 48)?),
                });
            }
        }
        at += cmdsize;
    }
    Ok(MachOLayout {
        cputype,
        text_vmaddr: text_vmaddr.ok_or(MeasureError::UnsupportedFormat)?,
        sections,
    })
}

/// Measures a thin 64-bit Mach-O file image.
pub fn measure_macho_file(image: &[u8]) -> Result<String, MeasureError> {
    let layout = parse_macho(image)?;
    let mut measurer = Measurer::new(ModuleFormat::MachO64);
    for section in &layout.sections {
        measurer.region(
            &section.label,
            section.addr,
            slice(image, section.file_offset, section.size)?,
        );
    }
    measurer.finish()
}

const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// A PE section selected for measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeSection {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
}

/// The PE section table entries a measurement uses, in table order.
pub fn parse_pe(image: &[u8]) -> Result<(u16, Vec<PeSection>), MeasureError> {
    if image.len() < 0x40 || &image[..2] != b"MZ" {
        return Err(MeasureError::UnsupportedFormat);
    }
    let pe = u64::from(u32_at(image, 0x3c)?);
    if slice(image, pe, 4)? != b"PE\0\0" {
        return Err(MeasureError::UnsupportedFormat);
    }
    let machine = u16_at(image, pe + 4)?;
    let count = u64::from(u16_at(image, pe + 6)?);
    let optional = u64::from(u16_at(image, pe + 20)?);
    let table = pe + 24 + optional;
    let mut sections = Vec::new();
    for index in 0..count {
        let s = table + index * 40;
        let characteristics = u32_at(image, s + 36)?;
        let raw_size = u32_at(image, s + 16)?;
        if characteristics & IMAGE_SCN_MEM_WRITE != 0 || raw_size == 0 {
            continue;
        }
        sections.push(PeSection {
            name: slice(image, s, 8)?.try_into().unwrap(),
            virtual_address: u32_at(image, s + 12)?,
            raw_offset: u32_at(image, s + 20)?,
            raw_size,
        });
    }
    Ok((machine, sections))
}

/// Measures a PE file image.
pub fn measure_pe_file(image: &[u8]) -> Result<String, MeasureError> {
    let (_, sections) = parse_pe(image)?;
    let mut measurer = Measurer::new(ModuleFormat::Pe);
    for section in &sections {
        measurer.region(
            &section.name,
            u64::from(section.virtual_address),
            slice(
                image,
                u64::from(section.raw_offset),
                u64::from(section.raw_size),
            )?,
        );
    }
    measurer.finish()
}

/// Measures a file image of any supported format.
pub fn measure_file_image(image: &[u8]) -> Result<String, MeasureError> {
    match image.get(..4) {
        Some(b"\x7fELF") => measure_elf_file(image),
        Some(magic) if magic == MH_MAGIC_64.to_le_bytes() => measure_macho_file(image),
        Some([b'M', b'Z', _, _]) => measure_pe_file(image),
        _ => Err(MeasureError::UnsupportedFormat),
    }
}

/// The running module that contains the updater, and its measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningModule {
    /// Loader-reported path, for diagnostics only (never trusted).
    pub path: String,
    pub measurement: String,
}

/// An address inside this module.
fn anchor() -> usize {
    measure_running_module as *const () as usize
}

/// Measures the module the process actually loaded this code from.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn measure_running_module() -> Result<RunningModule, MeasureError> {
    use std::ffi::CStr;
    use std::os::raw::{c_int, c_void};

    struct Search {
        anchor: usize,
        result: Option<Result<RunningModule, MeasureError>>,
    }

    unsafe extern "C" fn visit(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut c_void,
    ) -> c_int {
        // SAFETY: the loader passes a valid info record for the duration of
        // the callback, and `data` is the `Search` below.
        let (info, search) = unsafe { (&*info, &mut *(data as *mut Search)) };
        let base = info.dlpi_addr as usize;
        // SAFETY: dlpi_phdr points at dlpi_phnum program headers.
        let headers =
            unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize) };
        let contains = headers.iter().any(|h| {
            let start = base.wrapping_add(h.p_vaddr as usize);
            h.p_type == PT_LOAD
                && search.anchor >= start
                && search.anchor - start < h.p_memsz as usize
        });
        if !contains {
            return 0;
        }
        let format = if cfg!(target_pointer_width = "64") {
            ModuleFormat::Elf64
        } else {
            ModuleFormat::Elf32
        };
        let mut measurer = Measurer::new(format);
        for h in headers {
            let segment = ElfSegment {
                p_type: h.p_type,
                p_flags: h.p_flags,
                p_offset: h.p_offset as u64,
                p_vaddr: h.p_vaddr as u64,
                p_filesz: h.p_filesz as u64,
            };
            if segment.is_measured() {
                // SAFETY: a loaded, non-writable PT_LOAD segment is mapped
                // readable for at least p_filesz bytes at base + p_vaddr.
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        base.wrapping_add(h.p_vaddr as usize) as *const u8,
                        h.p_filesz as usize,
                    )
                };
                measurer.region(&[], segment.p_vaddr, bytes);
            }
        }
        let path = if info.dlpi_name.is_null() {
            String::new()
        } else {
            // SAFETY: dlpi_name is a NUL-terminated string owned by the loader.
            unsafe { CStr::from_ptr(info.dlpi_name) }
                .to_string_lossy()
                .into_owned()
        };
        search.result = Some(
            measurer
                .finish()
                .map(|measurement| RunningModule { path, measurement }),
        );
        1
    }

    let mut search = Search {
        anchor: anchor(),
        result: None,
    };
    // SAFETY: `visit` only dereferences loader-provided records and `search`.
    unsafe { libc::dl_iterate_phdr(Some(visit), &mut search as *mut Search as *mut c_void) };
    search
        .result
        .unwrap_or_else(|| Err(MeasureError::Unavailable("no loaded object".into())))
}

/// Measures the module the process actually loaded this code from.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn measure_running_module() -> Result<RunningModule, MeasureError> {
    use std::ffi::CStr;
    // SAFETY: Dl_info is plain data; dladdr fills it for a mapped address.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(anchor() as *const libc::c_void, &mut info) } == 0
        || info.dli_fbase.is_null()
    {
        return Err(MeasureError::Unavailable("dladdr failed".into()));
    }
    let header = info.dli_fbase as *const u8;
    // SAFETY: dli_fbase is the image's mapped mach_header_64; the header and
    // its sizeofcmds bytes of load commands are mapped readable.
    let fixed = unsafe { std::slice::from_raw_parts(header, 32) };
    if u32_at(fixed, 0)? != MH_MAGIC_64 {
        return Err(MeasureError::UnsupportedFormat);
    }
    let sizeofcmds = u32_at(fixed, 20)? as usize;
    let commands = unsafe { std::slice::from_raw_parts(header, 32 + sizeofcmds) };
    let layout = parse_macho(commands)?;
    let slide = (header as u64).wrapping_sub(layout.text_vmaddr);
    let mut measurer = Measurer::new(ModuleFormat::MachO64);
    for section in &layout.sections {
        // SAFETY: a section of a mapped, non-writable segment is readable
        // for `size` bytes at its slid address.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                section.addr.wrapping_add(slide) as usize as *const u8,
                section.size as usize,
            )
        };
        measurer.region(&section.label, section.addr, bytes);
    }
    let path = if info.dli_fname.is_null() {
        String::new()
    } else {
        // SAFETY: dli_fname is a NUL-terminated path owned by dyld.
        unsafe { CStr::from_ptr(info.dli_fname) }
            .to_string_lossy()
            .into_owned()
    };
    Ok(RunningModule {
        path,
        measurement: measurer.finish()?,
    })
}

/// Measures the module the process actually loaded this code from.
#[cfg(target_os = "windows")]
pub fn measure_running_module() -> Result<RunningModule, MeasureError> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::HMODULE;
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    };

    let mut module: HMODULE = std::ptr::null_mut();
    // SAFETY: the address is inside this module; the handle is not retained
    // beyond this call (UNCHANGED_REFCOUNT).
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            anchor() as *const u16,
            &mut module,
        )
    };
    if ok == 0 || module.is_null() {
        return Err(MeasureError::Unavailable(
            "GetModuleHandleExW failed".into(),
        ));
    }
    let mut buffer = vec![0u16; 512];
    let path = loop {
        // SAFETY: `buffer` has `len` writable u16s.
        let len = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) }
            as usize;
        if len == 0 {
            return Err(MeasureError::Unavailable(
                "GetModuleFileNameW failed".into(),
            ));
        }
        if len < buffer.len() {
            break std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len]));
        }
        if buffer.len() >= 32 * 1024 {
            return Err(MeasureError::Unavailable("module path too long".into()));
        }
        buffer.resize(buffer.len() * 2, 0);
    };
    // Read once and measure exactly the bytes read.
    let image = std::fs::read(&path).map_err(|e| MeasureError::Unavailable(e.to_string()))?;
    check_pe_mapping(module as usize, &image)?;
    Ok(RunningModule {
        path: path.to_string_lossy().into_owned(),
        measurement: measure_pe_file(&image)?,
    })
}

/// The loaded image's own section table must match the file that was
/// measured, so a file swapped after load (or a different file at the
/// reported path) is not mistaken for the mapped module. Section contents
/// are not compared in memory: base relocations legitimately change them.
#[cfg(target_os = "windows")]
fn check_pe_mapping(base: usize, file: &[u8]) -> Result<(), MeasureError> {
    // SAFETY: the module base maps the DOS header, PE headers and section
    // table read-only (SizeOfHeaders bytes, at least one page).
    let dos = unsafe { std::slice::from_raw_parts(base as *const u8, 0x40) };
    let pe = u32_at(dos, 0x3c)? as usize;
    let fixed = unsafe { std::slice::from_raw_parts(base as *const u8, pe + 24) };
    let count = u16_at(fixed, pe as u64 + 6)? as usize;
    let optional = u16_at(fixed, pe as u64 + 20)? as usize;
    let headers =
        unsafe { std::slice::from_raw_parts(base as *const u8, pe + 24 + optional + count * 40) };
    // The loader maps the headers verbatim (raw offsets and sizes included),
    // so the file parser reads the mapped table; it reads no section data.
    let (_, in_memory) = parse_pe(headers)?;
    let (_, on_disk) = parse_pe(file)?;
    if in_memory != on_disk {
        return Err(MeasureError::Unavailable(
            "loaded module differs from the file at its path".into(),
        ));
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "windows"
)))]
pub fn measure_running_module() -> Result<RunningModule, MeasureError> {
    Err(MeasureError::Unavailable("unsupported platform".into()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Synthetic images shared with flutter_tools'
    /// `shorebird_build_manifest_test.dart`; both pin the same golden values.
    pub fn elf64_fixture() -> Vec<u8> {
        let mut image = vec![0u8; 0x400];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2; // ELFCLASS64
        image[5] = 1; // little-endian
        image[6] = 1;
        image[0x10..0x12].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        image[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes()); // e_phoff
        image[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        image[0x38..0x3a].copy_from_slice(&3u16.to_le_bytes());
        // (type, flags, offset, vaddr, filesz): R+X text, RW data, R rodata.
        let segments = [
            (PT_LOAD, 5u32, 0x100u64, 0x1100u64, 0x80u64),
            (PT_LOAD, 6, 0x200, 0x2200, 0x40),
            (PT_LOAD, 4, 0x300, 0x3300, 0x20),
        ];
        for (i, (p_type, flags, offset, vaddr, filesz)) in segments.iter().enumerate() {
            let at = 0x40 + i * 56;
            image[at..at + 4].copy_from_slice(&p_type.to_le_bytes());
            image[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            image[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            image[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            image[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            image[at + 40..at + 48].copy_from_slice(&filesz.to_le_bytes());
        }
        for (i, byte) in image[0x100..0x400].iter_mut().enumerate() {
            *byte = (i * 7 % 251) as u8;
        }
        image
    }

    pub fn macho_fixture() -> Vec<u8> {
        let mut image = vec![0u8; 0x400];
        let put32 = |image: &mut Vec<u8>, at: usize, v: u32| {
            image[at..at + 4].copy_from_slice(&v.to_le_bytes())
        };
        let put64 = |image: &mut Vec<u8>, at: usize, v: u64| {
            image[at..at + 8].copy_from_slice(&v.to_le_bytes())
        };
        put32(&mut image, 0, MH_MAGIC_64);
        put32(&mut image, 4, 0x0100_000c); // CPU_TYPE_ARM64
        put32(&mut image, 12, 6); // MH_DYLIB
        put32(&mut image, 16, 2); // ncmds
        put32(&mut image, 20, 2 * 72 + 2 * 80 + 80); // sizeofcmds
                                                     // __TEXT: r-x, two sections (one zerofill to be skipped).
        let mut at = 32;
        put32(&mut image, at, LC_SEGMENT_64);
        put32(&mut image, at + 4, 72 + 2 * 80);
        image[at + 8..at + 14].copy_from_slice(b"__TEXT");
        put64(&mut image, at + 24, 0x1_0000_0000); // vmaddr
        put64(&mut image, at + 32, 0x400);
        put64(&mut image, at + 40, 0); // fileoff
        put64(&mut image, at + 48, 0x300);
        put32(&mut image, at + 56, 5);
        put32(&mut image, at + 60, 5); // initprot r-x
        put32(&mut image, at + 64, 2);
        let s = at + 72;
        image[s..s + 6].copy_from_slice(b"__text");
        image[s + 16..s + 22].copy_from_slice(b"__TEXT");
        put64(&mut image, s + 32, 0x1_0000_0200);
        put64(&mut image, s + 40, 0x60);
        put32(&mut image, s + 48, 0x200);
        let z = s + 80;
        image[z..z + 6].copy_from_slice(b"__bss0");
        image[z + 16..z + 22].copy_from_slice(b"__TEXT");
        put64(&mut image, z + 32, 0x1_0000_0300);
        put64(&mut image, z + 40, 0x10);
        put32(&mut image, z + 64, S_ZEROFILL);
        // __DATA: rw-, measured never.
        at += 72 + 2 * 80;
        put32(&mut image, at, LC_SEGMENT_64);
        put32(&mut image, at + 4, 72 + 80);
        image[at + 8..at + 14].copy_from_slice(b"__DATA");
        put64(&mut image, at + 24, 0x1_0000_0400);
        put64(&mut image, at + 40, 0x300);
        put64(&mut image, at + 48, 0x100);
        put32(&mut image, at + 60, 3);
        put32(&mut image, at + 64, 1);
        let d = at + 72;
        image[d..d + 6].copy_from_slice(b"__data");
        image[d + 16..d + 22].copy_from_slice(b"__DATA");
        put64(&mut image, d + 32, 0x1_0000_0400);
        put64(&mut image, d + 40, 0x40);
        put32(&mut image, d + 48, 0x300);
        for (i, byte) in image[0x200..0x400].iter_mut().enumerate() {
            *byte = (i * 13 % 251) as u8;
        }
        image
    }

    pub fn pe_fixture() -> Vec<u8> {
        let mut image = vec![0u8; 0x400];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0xaa64u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        let table = 0x80 + 24 + 0xf0;
        // (name, va, raw size, raw offset, characteristics)
        let sections = [
            (
                *b".text\0\0\0",
                0x1000u32,
                0x80u32,
                0x200u32,
                0x6000_0020u32,
            ),
            (*b".data\0\0\0", 0x2000, 0x40, 0x300, 0xc000_0040),
        ];
        for (i, (name, va, size, offset, ch)) in sections.iter().enumerate() {
            let at = table + i * 40;
            image[at..at + 8].copy_from_slice(name);
            image[at + 8..at + 12].copy_from_slice(&size.to_le_bytes());
            image[at + 12..at + 16].copy_from_slice(&va.to_le_bytes());
            image[at + 16..at + 20].copy_from_slice(&size.to_le_bytes());
            image[at + 20..at + 24].copy_from_slice(&offset.to_le_bytes());
            image[at + 36..at + 40].copy_from_slice(&ch.to_le_bytes());
        }
        for (i, byte) in image[0x200..0x400].iter_mut().enumerate() {
            *byte = (i * 31 % 251) as u8;
        }
        image
    }

    // Golden values shared with flutter_tools; change both or neither.
    pub const ELF64_GOLDEN: &str =
        "sha256:f177169245186be8e0fa2e8e6ffb9df70f8dd0824c8f305c06e17f30f63991cd";
    pub const MACHO_GOLDEN: &str =
        "sha256:33a600d96d0444bd5699f78f29c1643dd9e234fa03cbca06d85fc7d424572f60";
    pub const PE_GOLDEN: &str =
        "sha256:336fbd0090a289316b3d4d5d1801f4d2f41a699217b3d8c3df50ed99bfec927b";

    #[test]
    fn file_measurements_match_the_shared_golden_values() {
        assert_eq!(measure_file_image(&elf64_fixture()).unwrap(), ELF64_GOLDEN);
        assert_eq!(measure_file_image(&macho_fixture()).unwrap(), MACHO_GOLDEN);
        assert_eq!(measure_file_image(&pe_fixture()).unwrap(), PE_GOLDEN);
    }

    #[test]
    fn only_immutable_regions_are_measured() {
        // A writable segment/section changes nothing; any measured byte does.
        for (image, mutable, immutable) in [
            (elf64_fixture(), 0x210usize, 0x110usize),
            (macho_fixture(), 0x310, 0x210),
            (pe_fixture(), 0x310, 0x210),
        ] {
            let golden = measure_file_image(&image).unwrap();
            let mut changed = image.clone();
            changed[mutable] ^= 0xff;
            assert_eq!(measure_file_image(&changed).unwrap(), golden);
            let mut tampered = image.clone();
            tampered[immutable] ^= 0x01;
            assert_ne!(measure_file_image(&tampered).unwrap(), golden);
        }
    }

    #[test]
    fn code_signature_and_authenticode_regions_are_excluded() {
        // Mach-O: load-command padding and __LINKEDIT change on re-signing.
        let mut signed = macho_fixture();
        signed[0x1f0] = 0xaa; // padding after load commands, before __text
        assert_eq!(measure_file_image(&signed).unwrap(), MACHO_GOLDEN);
        // PE: checksum field and appended certificate data.
        let mut signed = pe_fixture();
        signed[0x80 + 24 + 64] = 0x55; // OptionalHeader.CheckSum
        signed.extend_from_slice(&[0x30; 64]);
        assert_eq!(measure_file_image(&signed).unwrap(), PE_GOLDEN);
    }

    #[test]
    fn malformed_images_are_refused_not_measured() {
        assert_eq!(
            measure_file_image(b"not a module"),
            Err(MeasureError::UnsupportedFormat)
        );
        let mut elf = elf64_fixture();
        elf[0x40 + 8..0x40 + 16].copy_from_slice(&0x3f0u64.to_le_bytes());
        assert_eq!(measure_file_image(&elf), Err(MeasureError::Truncated));
        let mut big_endian = elf64_fixture();
        big_endian[5] = 2;
        assert_eq!(
            measure_file_image(&big_endian),
            Err(MeasureError::UnsupportedFormat)
        );
        let mut pe = pe_fixture();
        pe[0x3c..0x40].copy_from_slice(&0x3fffu32.to_le_bytes());
        assert!(measure_file_image(&pe).is_err());
        let mut macho = macho_fixture();
        macho[20..24].copy_from_slice(&0xffffu32.to_le_bytes());
        assert_eq!(measure_file_image(&macho), Err(MeasureError::Truncated));
    }

    /// The in-memory measurement of the running test binary equals the
    /// file-based measurement of the same file: the runtime rule and the
    /// build-time rule agree on a real, loader-mapped module.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn running_module_measurement_equals_its_file_measurement() {
        let running = measure_running_module().unwrap();
        let exe = std::env::current_exe().unwrap();
        let file = measure_file_image(&std::fs::read(&exe).unwrap()).unwrap();
        assert_eq!(running.measurement, file, "{}", running.path);
        // The loader target is the module actually measured: another binary
        // (a changed loader target) never yields the same value.
        assert_ne!(
            measure_file_image(&macho_fixture()).unwrap(),
            running.measurement
        );
    }
}
