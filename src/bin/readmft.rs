extern crate rpki;

use std::{env, fs, path::PathBuf};
use rpki::{repository::manifest::{Manifest,}, rrdp};


fn main() {
    if let Err(e) = process() {
        eprintln!("{e}");
        ::std::process::exit(1);
    }
}

fn process() -> Result<(), String> {
    let usage = usage()?;
    let manifest = read_manifest(&usage)?;
    if usage.print {
        print_manifest(manifest)?;
    }
    Ok(())
}

fn print_manifest(manifest: Manifest) -> Result<(), String> {
    let mft_uri = manifest
        .cert()
        .signed_object()
        .ok_or( "Manifest EE lacks signed object URI")?;

    let base_uri = mft_uri.parent()
        .ok_or_else(|| format!("Manifest URI as no parent: {mft_uri}"))?;

    println!("This update: {}", manifest.this_update().to_rfc3339());
    println!("Next update: {}", manifest.next_update().to_rfc3339());
    println!("Number:      {}", manifest.manifest_number());
    println!();
    println!("File List:");
    for (uri, hash) in manifest.iter_uris(&base_uri) {
        let hash = hash.hex_encode();
        println!("{hash} {uri}");
    }

    Ok(())
}

fn read_manifest(usage: &Usage) -> Result<Manifest, String> {
    let data = fs::read(&usage.file)
        .map_err(|err| format!("Can’t read file: {err}"))?;

    if usage.print {
        let hash = rrdp::Hash::from_data(&data);        
        println!("File Hash:   {hash}");
    }

    Manifest::decode(data.as_ref(), false)
        .map_err(|err| format!("Can't decode manifest: {err}"))
}

fn usage() -> Result<Usage, String> {
    let usage = "Usage: readmft <path> [print]";
    if env::args().len() < 2 || env::args().len() > 3 {
        Err(usage.to_string())
    } else {
        let file = env::args().nth(1).map(PathBuf::from).ok_or(usage)?;
        if let Some(arg) = env::args().nth(2) {
            if &arg != "print" {
                Err(format!("Unexpected argument: {arg}"))
            } else {
                Ok(Usage { file, print: true })
            }
        } else {
            Ok(Usage { file, print: false })
        }
    }
}

struct Usage {
    file: PathBuf,
    print: bool,
}



