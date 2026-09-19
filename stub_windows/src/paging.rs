//! Paginação opcional das seções executáveis; o VEH libera cada página no primeiro acesso.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use sha2::{Digest, Sha256};

const PAGE_SIZE: usize = 4096;

/// Limite de páginas em claro. Mantenha 0 para payloads multithread.

const REENCRYPT_WINDOW: usize = 0;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualProtect(addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
    fn AddVectoredExceptionHandler(first: u32, handler: VehHandler) -> *mut c_void;
    fn FlushInstructionCache(proc_: *mut c_void, base: *const c_void, size: usize) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
}

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut c_void,
        buffer: *mut u8,
        buffer_len: u32,
        flags: u32,
    ) -> i32;
}

const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READWRITE: u32 = 0x04;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

type VehHandler = unsafe extern "system" fn(*mut ExceptionPointers) -> i32;

#[repr(C)]
struct ExceptionRecord {
    code: u32,
    flags: u32,
    record: *mut ExceptionRecord,
    address: *mut c_void,
    number_parameters: u32,
    information: [usize; 15],
}

#[repr(C)]
struct ExceptionPointers {
    exception_record: *mut ExceptionRecord,
    context_record: *mut c_void,
}

/// Faixa de páginas fornecida pelo loader.

pub struct Range {
    pub rva: usize,
    pub len: usize,
    pub prot: u32,
}

#[derive(Clone, Copy)]
struct PageInfo {
    managed: bool,
    plain: bool,
    prot: u32,
}

struct Paging {
    base: *mut u8,
    total_pages: usize,
    key: [u8; 32],
    lock: AtomicBool,
    pages: UnsafeCell<Vec<PageInfo>>,
    fifo: UnsafeCell<Vec<usize>>,
}

// `pages` e `fifo` são protegidos pelo spinlock; base e chave não mudam após `arm()`.

unsafe impl Sync for Paging {}
unsafe impl Send for Paging {}

impl Paging {
    #[inline]
    fn acquire(&self) {
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    #[inline]
    fn release(&self) {
        self.lock.store(false, Ordering::Release);
    }
}

static STATE: AtomicPtr<Paging> = AtomicPtr::new(core::ptr::null_mut());

/// Keystream em contador SHA-256 usado apenas para mascarar páginas.

fn xor_page(key: &[u8; 32], page_index: usize, data: &mut [u8]) {
    let mut counter: u64 = 0;
    let mut off = 0usize;

    while off < data.len() {
        let mut h = Sha256::new();
        h.update(key);
        h.update(&(page_index as u64).to_le_bytes());
        h.update(&counter.to_le_bytes());
        let block = h.finalize();

        let n = core::cmp::min(32, data.len() - off);
        for i in 0..n {
            data[off + i] ^= block[i];
        }

        off += n;
        counter = counter.wrapping_add(1);
    }
}

/// Restaura a proteção final antes de publicar a página como disponível.

unsafe fn transform_page(
    base: *mut u8,
    key: &[u8; 32],
    page_index: usize,
    final_prot: u32,
) -> bool {
    unsafe {
        let addr = base.add(page_index * PAGE_SIZE) as *mut c_void;

        let mut old = 0u32;
        if VirtualProtect(addr, PAGE_SIZE, PAGE_READWRITE, &mut old) == 0 {
            return false;
        }

        let slice = core::slice::from_raw_parts_mut(addr as *mut u8, PAGE_SIZE);
        xor_page(key, page_index, slice);

        let mut old2 = 0u32;
        if VirtualProtect(addr, PAGE_SIZE, final_prot, &mut old2) == 0 {
            return false;
        }

        FlushInstructionCache(GetCurrentProcess(), addr as *const c_void, PAGE_SIZE);
        true
    }
}

unsafe extern "system" fn handler(info: *mut ExceptionPointers) -> i32 {
    unsafe {
        if info.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let record = (*info).exception_record;
        if record.is_null() || (*record).code != STATUS_ACCESS_VIOLATION {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if (*record).number_parameters < 2 {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let state = STATE.load(Ordering::Acquire);
        if state.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let st = &*state;

        // Endereço que causou a falta.

        let fault = (*record).information[1];
        let lo = st.base as usize;
        let hi = match lo.checked_add(st.total_pages * PAGE_SIZE) {
            Some(v) => v,
            None => return EXCEPTION_CONTINUE_SEARCH,
        };
        if fault < lo || fault >= hi {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let page = (fault - lo) / PAGE_SIZE;

        st.acquire();

        let pages = &mut *st.pages.get();
        let info_page = match pages.get(page).copied() {
            Some(v) => v,
            None => {
                st.release();
                return EXCEPTION_CONTINUE_SEARCH;
            }
        };

        if !info_page.managed {
            st.release();
            return EXCEPTION_CONTINUE_SEARCH;
        }

        if info_page.plain {
            // Outra thread resolveu esta página enquanto aguardávamos o lock.

            st.release();
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        let ok = transform_page(st.base, &st.key, page, info_page.prot);
        if !ok {
            st.release();
            return EXCEPTION_CONTINUE_SEARCH;
        }
        pages[page].plain = true;

        if REENCRYPT_WINDOW > 0 {
            let fifo = &mut *st.fifo.get();
            fifo.push(page);
            while fifo.len() > REENCRYPT_WINDOW {
                let victim = fifo.remove(0);
                if victim == page {
                    continue;
                }
                if let Some(v) = pages.get(victim).copied() {
                    if v.managed && v.plain
                        && transform_page(st.base, &st.key, victim, PAGE_NOACCESS)
                    {
                        pages[victim].plain = false;
                    }
                }
            }
        }

        st.release();
        EXCEPTION_CONTINUE_EXECUTION
    }
}

pub unsafe fn arm(base: *mut u8, size_of_image: usize, ranges: &[Range]) -> Result<(), ()> {
    if base.is_null() || size_of_image < PAGE_SIZE || ranges.is_empty() {
        return Err(());
    }
    if !STATE.load(Ordering::Acquire).is_null() {
        return Err(());
    }

    let mut key = [0u8; 32];
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            key.as_mut_ptr(),
            key.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(());
    }

    let total_pages = size_of_image / PAGE_SIZE;
    if total_pages == 0 {
        return Err(());
    }

    let mut pages = vec![
        PageInfo {
            managed: false,
            plain: false,
            prot: 0,
        };
        total_pages
    ];

    for r in ranges {
        if r.rva % PAGE_SIZE != 0 || r.len == 0 {
            continue;
        }
        let first = r.rva / PAGE_SIZE;
        let count = r.len / PAGE_SIZE;
        for p in first..first.saturating_add(count) {
            if p >= total_pages {
                break;
            }
            // O arredondamento de seções pode fazer duas faixas tocarem a mesma página.

            if pages[p].managed {
                continue;
            }
            pages[p].managed = true;
            pages[p].plain = true; // ainda em claro neste instante
            pages[p].prot = r.prot;
        }
    }

    let state = Box::new(Paging {
        base,
        total_pages,
        key,
        lock: AtomicBool::new(false),
        pages: UnsafeCell::new(pages),
        fifo: UnsafeCell::new(Vec::new()),
    });
    let state = Box::leak(state) as *mut Paging;

    let veh = unsafe { AddVectoredExceptionHandler(1, handler) };
    if veh.is_null() {
        unsafe { drop(Box::from_raw(state)) };
        return Err(());
    }

    STATE.store(state, Ordering::Release);

    let st = unsafe { &*state };
    st.acquire();
    let pages = unsafe { &mut *st.pages.get() };
    for p in 0..total_pages {
        if !pages[p].managed || !pages[p].plain {
            continue;
        }
        if unsafe { transform_page(base, &st.key, p, PAGE_NOACCESS) } {
            pages[p].plain = false;
        } else {
            // Se a proteção falhar, a página fica fora do gerenciamento.

            pages[p].managed = false;
        }
    }
    st.release();

    Ok(())
}

/// Retorna (páginas gerenciadas, páginas em claro) para diagnóstico.

#[allow(dead_code)]
pub fn plaintext_pages() -> (usize, usize) {
    let state = STATE.load(Ordering::Acquire);
    if state.is_null() {
        return (0, 0);
    }
    let st = unsafe { &*state };
    st.acquire();
    let pages = unsafe { &*st.pages.get() };
    let managed = pages.iter().filter(|p| p.managed).count();
    let plain = pages.iter().filter(|p| p.managed && p.plain).count();
    st.release();
    (plain, managed)
}
