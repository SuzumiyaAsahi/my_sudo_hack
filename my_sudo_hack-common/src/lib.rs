#![no_std]
#[no_mangle]
pub static mut uid: u32 = 0;

#[no_mangle]
pub static mut payload_len: u64 = 0;

pub const MAX_PAYLOAD_LEN: usize = 100;

#[no_mangle]
pub static mut payload: [u8; MAX_PAYLOAD_LEN as usize] = [0; MAX_PAYLOAD_LEN as usize];
