#![no_main]

use libfuzzer_sys::fuzz_target;
use rpki::repository::{Aspa, Cert, Crl, Manifest, Roa, Tal};

fuzz_target!(|data: &[u8]| {
    let (which, mut data) = match data.split_first() {
        Some((first, data)) => (*first, data),
        None => return,
    };

    match which % 9 {
        0 => { let _ = Cert::decode(data); },
        1 => { let _ = Crl::decode(data); },
        2 => { let _ = Manifest::decode(data, false); },
        3 => { let _ = Manifest::decode(data, true); },
        4 => { let _ = Roa::decode(data, false); },
        5 => { let _ = Roa::decode(data, true); },
        6 => { let _ = Aspa::decode(data, false); },
        7 => { let _ = Aspa::decode(data, true); },
        8 => { let _ = Tal::read_named("foo".into(), &mut data); },
        _ => panic!("what?"),
    }
});

