#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    // Test with msg_id 1 (any id; parser rejects mismatches with Protocol err, not panic)
    let _ = ad_time::protocols::cldap::fuzz_parse_cldap_response(data, 1);
});
