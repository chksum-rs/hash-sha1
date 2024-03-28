#![no_main]

use chksum_hash_sha1 as sha1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|hash: sha1::Update| {
    {
        let mut hash = hash.clone();

        // Update with nothing
        let _ = hash.update(b"").digest();
    }

    {
        let mut hash = hash.clone();

        // Update with byte
        let _ = hash.update(b"\0").digest();
    }

    {
        let mut hash = hash.clone();

        // Update with bytes
        let _ = hash.update(b"data").digest();
    }

    {
        let mut hash = hash.clone();

        // Update with bytes
        let _ = hash.update(b"\x00").update(b"\x01").digest();
    }
});
