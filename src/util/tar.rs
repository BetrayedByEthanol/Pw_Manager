use std::fs::File;
use std::path::Path;
use std::process::Command;
use flate2::Compression;
use flate2::read::GzDecoder;

use flate2::write::GzEncoder;
use tar::Builder;

fn compress() -> Result<(), Box<dyn std::error::Error>> {
    let source = Path::new("/tmp/tar_test");
    let target = Path::new("/tmp/test.tar.gz");


    let tar_gz = File::create(target)?;
    let enc = GzEncoder::new(tar_gz, Compression::default());

    let mut tar = Builder::new(enc);

    tar.append_dir_all(source.file_name().unwrap() , source)?;

    tar.finish()?;
    Ok(())
}

fn decompress() -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("ls").arg("/tmp").output()?;
    println!(
        "{}",
        String::from_utf8(status.stdout).expect("Our bytes should be valid utf8")
    );
    let target = Path::new("/tmp/test.tar.gz");
    let output_dir = Path::new("/tmp/tar_out");
    let tar_gz = File::open(target)?;

    let tar = GzDecoder::new(tar_gz);

    let mut archive = tar::Archive::new(tar);

    archive.unpack(output_dir)?;

    Ok(())
}