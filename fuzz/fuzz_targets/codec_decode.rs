#![no_main]

use libfuzzer_sys::fuzz_target;
use mfn_crypto::Reader;

fuzz_target!(|data: &[u8]| {
    let _ = Reader::new(data).varint();
    let _ = Reader::new(data).blob();
    let _ = Reader::new(data).points();
    let _ = Reader::new(data).scalars();
});
