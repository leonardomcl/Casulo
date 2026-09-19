//! Handshake simples via VEH antes do caminho convencional de execução em disco.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

// Código privado e continuável da exceção.

const CASULO_EXEC_DISK_EXCEPTION: u32 = 0xE084_4344;

const STATE_IDLE: u32 = 0;
const STATE_ARMED: u32 = 1;
const STATE_HANDLED: u32 = 2;

static STATE: AtomicU32 = AtomicU32::new(STATE_IDLE);
static OWNER_THREAD: AtomicU32 = AtomicU32::new(0);

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

type VehHandler = unsafe extern "system" fn(*mut ExceptionPointers) -> i32;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn AddVectoredExceptionHandler(first: u32, handler: VehHandler) -> *mut c_void;
    fn RemoveVectoredExceptionHandler(handle: *mut c_void) -> u32;
    fn RaiseException(code: u32, flags: u32, count: u32, args: *const usize);
    fn GetCurrentThreadId() -> u32;
}

struct VehGuard {
    handle: *mut c_void,
}

impl VehGuard {
    fn install() -> Option<Self> {
        // Instala depois do VEH de paging, que ignora este código.

        let handle = unsafe { AddVectoredExceptionHandler(0, handler) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }
}

impl Drop for VehGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = RemoveVectoredExceptionHandler(self.handle);
            }
            self.handle = core::ptr::null_mut();
        }
    }
}

unsafe extern "system" fn handler(info: *mut ExceptionPointers) -> i32 {
    unsafe {
        if info.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let record = (*info).exception_record;
        if record.is_null() || (*record).code != CASULO_EXEC_DISK_EXCEPTION {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // Somente a thread que armou o pedido pode consumi-lo.

        let current_thread = GetCurrentThreadId();
        if OWNER_THREAD.load(Ordering::Acquire) != current_thread {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // Transição válida: ARMED -> HANDLED.

        if STATE
            .compare_exchange(
                STATE_ARMED,
                STATE_HANDLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        EXCEPTION_CONTINUE_EXECUTION
    }
}

/// Retorna true somente se a exceção privada desta thread foi tratada.

#[inline(never)]
pub fn request_disk_execution() -> bool {
    let _guard = match VehGuard::install() {
        Some(v) => v,
        None => return false,
    };

    let tid = unsafe { GetCurrentThreadId() };
    OWNER_THREAD.store(tid, Ordering::Release);

    if STATE
        .compare_exchange(
            STATE_IDLE,
            STATE_ARMED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        OWNER_THREAD.store(0, Ordering::Release);
        return false;
    }

    unsafe {
        RaiseException(
            CASULO_EXEC_DISK_EXCEPTION,
            0,
            0,
            core::ptr::null(),
        );
    }

    let handled = STATE.load(Ordering::Acquire) == STATE_HANDLED;

    // Deixa o estado pronto para uma chamada futura no mesmo processo.

    STATE.store(STATE_IDLE, Ordering::Release);
    OWNER_THREAD.store(0, Ordering::Release);

    handled
}
