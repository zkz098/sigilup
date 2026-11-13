#![no_main]

use libfuzzer_sys::fuzz_target;
use sigilup_manifest::UrlPolicy;

fuzz_target!(|data: &[u8]| {
    if let Ok(raw_url) = std::str::from_utf8(data) {
        let _ = UrlPolicy::https_only().validate(raw_url);

        let prefix_policy =
            UrlPolicy::with_prefixes(["https://github.com/zkz098/sigilup/releases/download/"]);
        let _ = prefix_policy.validate(raw_url);

        let host_policy = UrlPolicy {
            require_https: false,
            allowed_hosts: vec!["downloads.example.com".to_string()],
            ..UrlPolicy::default()
        };
        let _ = host_policy.validate(raw_url);
    }
});
