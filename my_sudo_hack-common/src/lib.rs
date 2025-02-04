#![no_std]
#[no_mangle]
pub static mut uid: u64 = 0;

#[no_mangle]
pub static mut payload_len: u64 = 0;

pub const max_payload_len: u32 = 100;

#[no_mangle]
pub static mut payload: [u8; max_payload_len as usize] = [0; max_payload_len as usize];
