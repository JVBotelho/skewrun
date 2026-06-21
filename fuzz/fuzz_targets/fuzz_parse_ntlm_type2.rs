#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = ad_time::protocols::ntlm::fuzz_parse_ntlm_type2(data);
});
