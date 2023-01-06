/// Adapted from the Aya example

use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

 
pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("./");
    let names: Vec<&str> = vec!["iphdr","ipv6hdr"];
    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{}", bindings)?;

    Ok(())
}
