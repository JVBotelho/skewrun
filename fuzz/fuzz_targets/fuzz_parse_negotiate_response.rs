#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = ad_time::protocols::smb::fuzz_parse_negotiate_response(data);
});
