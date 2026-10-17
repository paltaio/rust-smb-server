#![no_main]

use libfuzzer_sys::fuzz_target;

mod server;

// SMB1 header with the NEGOTIATE command and WordCount 0. The input supplies
// ByteCount and the dialect strings.
const PREFIX: [u8; 33] = {
    let mut p = [0u8; 33];
    p[0] = 0xFF;
    p[1] = b'S';
    p[2] = b'M';
    p[3] = b'B';
    p[4] = 0x72;
    p
};

fuzz_target!(|data: &[u8]| {
    let mut frame = PREFIX.to_vec();
    frame.extend_from_slice(data);
    server::dispatch(&frame);
});
