extern crate rpki;

use std::{env, fs};
use rpki::repository::cert::Cert;


fn main() {
    let path = match env::args().nth(1) {
        Some(path) => path,
        None => {
            println!("Usage: readcert <path>");
            return
        }
    };
    let data = match fs::read(path) {
        Ok(file) => file,
        Err(err) => {
            println!("Can’t read file: {}", err);
            return;
        }
    };
    let _cert = match Cert::decode(data.as_ref()) {
        Ok(cert) => cert,
        Err(err) => {
            println!("Can’t decode cert: {}", err);
            return
        }
    };
}

