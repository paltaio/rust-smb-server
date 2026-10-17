#![no_main]

use libfuzzer_sys::fuzz_target;

mod server;

fuzz_target!(|data: &[u8]| server::dispatch(data));
