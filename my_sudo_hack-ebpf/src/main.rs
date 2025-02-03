#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use my_sudo_hack_common::uid;

#[map]
// Map to hold the File Descriptors from 'openat' calls
static map_fds: HashMap<usize, u32> = HashMap::<usize, u32>::with_max_entries(8192, 0);

#[map]
// Map to hold the buffer sized from 'read' calls
static map_buff_addrs: HashMap<usize, u32> = HashMap::<usize, u32>::with_max_entries(8192, 0);

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
    info!(&ctx, "tracepoint syscalls called");
    Ok(0)
}

fn handle_openat_exit_function(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint syscalls called");
    Ok(0)
}

fn handle_read_enter_function(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint syscalls called");
    Ok(0)
}

fn handle_read_exit_function(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint syscalls called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
