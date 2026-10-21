#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| smb_server::fuzzing::lease_context(data));
