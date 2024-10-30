// Copyright (C) 2023 Ant Group CO., Ltd. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use {
    crate::cpumask::{CpuMask, CPU_MASK_LEN},
    crate::error::HvResult,
    crate::header::HvHeader,
    crate::memory::{self, addr},
    crate::percpu::PerCpu,
    crate::{hv_err, hv_result_err},
    bitflags::bitflags,
    core::fmt,
    core::sync::atomic::{AtomicUsize, Ordering},
    log::{self, Level, LevelFilter, Log, Metadata, Record},
    spin::mutex::SpinMutex,
};

use {core::cmp, core::mem::size_of, core::slice};

pub fn init() {
    log::set_logger(&SimpleLogger).unwrap();
    log::set_max_level(match option_env!("LOG") {
        Some("error") => LevelFilter::Error,
        Some("warn") => LevelFilter::Warn,
        Some("info") => LevelFilter::Info,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        _ => LevelFilter::Off,
    });
}

#[cfg(not(test))]
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        $crate::logging::print(format_args!($($arg)*));
    });
}

#[cfg(not(test))]
#[macro_export]
macro_rules! println {
    ($fmt:expr) => (print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!($fmt, "\n"), $($arg)*));
}

/// Add escape sequence to print with color in Linux console
macro_rules! with_color {
    ($args: ident, $color_code: ident) => {{
        format_args!("\u{1B}[{}m{}\u{1B}[0m", $color_code as u8, $args)
    }};
}

fn print_in_color(args: fmt::Arguments, color_code: u8) {
    if INIT_HHBOX_LOG_OK.load(Ordering::Acquire) == 1 {
        log_store(&format!("[{}] {}", PerCpu::from_local_base().cpu_id, args)[..]);
    }
    crate::arch::serial::putfmt(with_color!(args, color_code));
}

#[allow(dead_code)]
pub fn print(args: fmt::Arguments) {
    if INIT_HHBOX_LOG_OK.load(Ordering::Acquire) == 1 {
        log_store(&format!("[{}] {}", PerCpu::from_local_base().cpu_id, args)[..]);
    }
    crate::arch::serial::putfmt(args);
}

struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        print_in_color(
            format_args!(
                "[{}][{}] {}\n",
                record.level(),
                crate::arch::cpu::id(),
                record.args(),
            ),
            level_to_color_code(record.level()),
        );
    }
    fn flush(&self) {}
}

fn level_to_color_code(level: Level) -> u8 {
    match level {
        Level::Error => 31, // Red
        Level::Warn => 93,  // BrightYellow
        Level::Info => 34,  // Blue
        Level::Debug => 32, // Green
        Level::Trace => 90, // BrightBlack
    }
}

const LOGENTRY_SIZE: usize = 160;
#[repr(C)]
struct HeLogEntry {
    buf: [u8; LOGENTRY_SIZE],
    used: bool,
}

#[repr(C)]
struct HeLog {
    log_lost: u32,
    num: usize,
    // log array here, flexible member size.
}

impl HeLog {
    fn log_ptr(&mut self) -> *mut HeLogEntry {
        // SAFETY: HeLog has a flexible member.
        unsafe { (self as *mut HeLog).add(1) as _ }
    }

    fn get_logentries(&mut self) -> &mut [HeLogEntry] {
        // SAFETY: log_ptr and num are validated upon initialization.
        unsafe { slice::from_raw_parts_mut(self.log_ptr(), self.get_num()) }
    }

    // HeLog.num might be modified by untrusted driver. Instead, HE_LOG_SIZE
    // has been validated.
    fn get_num(&self) -> usize {
        *HE_LOG_SIZE
    }

    fn validate_addr(&self) -> bool {
        let pa = HvHeader::get().he_log_pa as usize;
        // HE_LOG_SIZE is not set at this time.
        if memory::is_normal_memory(pa, size_of::<HeLog>() + self.num * size_of::<HeLogEntry>())
            .is_err()
        {
            return false;
        }
        true
    }

    fn fill_log(&mut self, index: usize, bytes: &[u8]) {
        use core::sync::atomic::fence;
        // Drop incoming logs when the ring buffer is full.
        let log = self.get_logentries();
        if log[index].used {
            self.log_lost += 1;
            return;
        }

        let len = bytes.len();
        log[index].buf[..len].clone_from_slice(&bytes[..len]);
        log[index].buf[len] = b'\0';
        // Invariant: if c-driver sees `used` set, the buffer should be valid.
        fence(Ordering::Release);
        log[index].used = true;
    }
}

fn log_store(s: &str) {
    let s_len = s.bytes().len();
    let s_bytes = s.as_bytes();
    static LAST_LOG_INDEX: AtomicUsize = AtomicUsize::new(0);

    if s_len == 0 {
        return;
    }

    // If a log is too long, claim multiple slots and split the long log.
    // LOGENTRY_SIZE - 1 for '\0'
    let nr_slots = if s_len % (LOGENTRY_SIZE - 1) == 0 {
        s_len / (LOGENTRY_SIZE - 1)
    } else {
        1 + s_len / (LOGENTRY_SIZE - 1)
    };

    // SAFETY: HE_LOG_VA is validated before.
    let he_log_ref = unsafe { &mut *((*HE_LOG_VA) as *mut HeLog) };
    let start_index = LAST_LOG_INDEX.fetch_add(nr_slots, Ordering::SeqCst) % he_log_ref.get_num();

    for i in 0..nr_slots {
        let index = (start_index + i) % he_log_ref.get_num();
        let start_pos = i * (LOGENTRY_SIZE - 1);
        let end_pos = cmp::min((i + 1) * (LOGENTRY_SIZE - 1), s_len);
        he_log_ref.fill_log(index, &s_bytes[start_pos..end_pos]);
    }
}

lazy_static! {
    static ref HE_LOG_VA: usize = {
        let he_log_pa = HvHeader::get().he_log_pa as usize;
        if memory::is_normal_memory(he_log_pa, size_of::<HeLog>()).is_err() {
            return 0;
        }
        addr::phys_to_virt(he_log_pa)
    };
    // he_log_pa and he_log_pa + size should stay in the normal memory.
    static ref HE_LOG_SIZE: usize = {
        if *HE_LOG_VA == 0 {
            return 0;
        }
        // SAFETY: HE_LOG_VA is validated before.
        let he_log_ref = unsafe { &mut *((*HE_LOG_VA) as *mut HeLog) };
        if !he_log_ref.validate_addr() {
            return 0;
        }
        he_log_ref.num
    };
}

bitflags! {
    /// HyperEnclave features.
    pub struct HEFeature: u64 {
        const HHBOX_LOG        = 1 << 0;
        const HHBOX_CRASH      = 1 << 1;
    }
}

static INIT_HHBOX_LOG_OK: AtomicUsize = AtomicUsize::new(0);
static INIT_HHBOX_CRASH_OK: AtomicUsize = AtomicUsize::new(0);

pub fn hhbox_init() -> HvResult {
    let header = HvHeader::get();

    println!("max cpus: {}", header.max_cpus);
    info!("HyperEnclave features: {:?}", header.feature_mask);
    if header.feature_mask.contains(HEFeature::HHBOX_LOG) {
        if *HE_LOG_VA == 0 || *HE_LOG_SIZE == 0 {
            return hv_result_err!(
                EFAULT,
                "Invalid he log shared \
                buffer address or size."
            );
        }
        INIT_HHBOX_LOG_OK.store(1, Ordering::Release);
        println!("Init HHBox log feature ok");
    }

    if header.feature_mask.contains(HEFeature::HHBOX_CRASH) {
        if *VMM_ANOMALY_CPUS_VA == 0 {
            return hv_result_err!(EFAULT, "Invalid vmm_anomaly_cpus addr");
        }
        INIT_HHBOX_CRASH_OK.store(1, Ordering::Release);
        println!("Init HHBox crash feature ok");
    }

    Ok(())
}

pub fn hhbox_disable() {
    INIT_HHBOX_LOG_OK.store(0, Ordering::Release);
    INIT_HHBOX_CRASH_OK.store(0, Ordering::Release);
}

pub fn set_vmm_anomaly_cpus(cpuid: usize, state: bool) {
    if INIT_HHBOX_CRASH_OK.load(Ordering::Acquire) == 1 {
        static VMM_STATE_LOCK: SpinMutex<()> = SpinMutex::new(());
        // SAFETY: VMM_ANOMALY_CPUS_VA is validated before.
        let vmm_anomaly_cpus = unsafe { &mut *((*VMM_ANOMALY_CPUS_VA) as *mut CpuMask) };
        let _lock = VMM_STATE_LOCK.lock();

        if state {
            vmm_anomaly_cpus.set_cpu(cpuid);
        } else {
            vmm_anomaly_cpus.clear_cpu(cpuid);
        }
    }
}

lazy_static! {
    static ref VMM_ANOMALY_CPUS_VA: usize = {
        let vmm_anomaly_cpus_pa = HvHeader::get().vmm_anomaly_cpus_pa as usize;
        if memory::is_normal_memory(vmm_anomaly_cpus_pa, CPU_MASK_LEN).is_err() {
            return 0;
        }
        addr::phys_to_virt(vmm_anomaly_cpus_pa)
    };
}
