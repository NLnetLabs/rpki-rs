#![no_main]

use libfuzzer_sys::fuzz_target;
use rpki::rrdp;

fuzz_target!(|data: &[u8]| {
    let Some((first, data)) = data.split_first() else { return };

    match first {
        0 => {
            let _ = rrdp::NotificationFile::parse(data);
        }
        1 => {
            let _ = rrdp::Snapshot::parse(data);
        }
        2 => {
            let _ = rrdp::Delta::parse(data);
        }
        _ => { }
    }

});

