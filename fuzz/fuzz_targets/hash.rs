#![no_main]

use chksum_hash_sha1 as sha1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sha1::hash(data);
});
