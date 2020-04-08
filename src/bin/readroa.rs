extern crate rpki;

use std::{env, fs};
use rpki::roa::Roa;


fn main() {
    let path = match env::args().nth(1) {
        Some(path) => path,
        None => {
            println!("Usage: readroa <path>");
            return
        }
    };
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) => {
            println!("Can’t read file: {}", err);
            return;
        }
    };

    let _cert = match Roa::decode(data.as_ref(), true) {
        Ok(cert) => cert,
        Err(err) => {
            println!("Can’t decode roa: {}", err);
            return
        }
    };
}


