extern crate rpki;

use std::{env, fs};
use rpki::repository::manifest::Manifest;


fn main() {
    let path = match env::args().nth(1) {
        Some(path) => path,
        None => {
            println!("Usage: readmft <path>");
            return
        }
    };
    let data = match fs::read(path) {
        Ok(file) => file,
        Err(err) => {
            println!("Can’t read file: {err}");
            return;
        }
    };
    let _cert = match Manifest::decode(data.as_ref(), false) {
        Ok(cert) => cert,
        Err(err) => {
            println!("Can’t decode manifest: {err}");
            return
        }
    };
}


