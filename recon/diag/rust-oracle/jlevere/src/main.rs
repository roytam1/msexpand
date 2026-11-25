use std::env;
use std::fs;
use std::process;

fn read(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("read {path}: {error}"))
}

fn write(path: &str, data: &[u8]) -> Result<(), String> {
    fs::write(path, data).map_err(|error| format!("write {path}: {error}"))
}

fn usage() {
    eprintln!(
        "Usage:\n  msdelta-jlevere apply <source> <delta> <output>\n  msdelta-jlevere create <source> <target> <delta-output> [raw|auto|pa31|bsdiff]\n  msdelta-jlevere reverse <source> <delta> <target-output> <reverse-output>"
    );
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        return Err("missing command".to_string());
    }

    match args[1].as_str() {
        "apply" => {
            if args.len() != 5 {
                usage();
                return Err("apply needs source, delta, and output".to_string());
            }
            let source = read(&args[2])?;
            let delta = read(&args[3])?;
            let output = msdelta::pa30::apply(&source, &delta)
                .map_err(|error| format!("jlevere: {error}"))?;
            write(&args[4], &output)
        }
        "create" => {
            if args.len() != 5 && args.len() != 6 {
                usage();
                return Err("create needs source, target, output, and optional mode".to_string());
            }
            let source = read(&args[2])?;
            let target = read(&args[3])?;
            let mode = if args.len() == 6 {
                args[5].as_str()
            } else {
                "raw"
            };
            let mut options =
                msdelta::pa30::CreateOptions::new().hash_algorithm(msdelta::pa30::HASH_ALG_SHA256);
            let delta = match mode {
                "raw" => options.execute(&source, &target),
                "auto" => {
                    options = options.file_type(msdelta::pa30::FileType::Auto);
                    options.execute(&source, &target)
                }
                "pa31" => {
                    options = options.version(msdelta::pa30::FormatVersion::PA31);
                    options.execute(&source, &target)
                }
                "bsdiff" => {
                    options = options
                        .version(msdelta::pa30::FormatVersion::PA31)
                        .codec(msdelta::pa30::Codec::BsDiff);
                    options.execute(&source, &target)
                }
                value => return Err(format!("unknown create mode: {value}")),
            }
            .map_err(|error| format!("jlevere create: {error}"))?;
            write(&args[4], &delta)
        }
        "reverse" => {
            if args.len() != 6 {
                usage();
                return Err(
                    "reverse needs source, delta, target output, and reverse output".to_string(),
                );
            }
            let source = read(&args[2])?;
            let delta = read(&args[3])?;
            let (target, reverse) = msdelta::pa30::apply_get_reverse(&source, &delta)
                .map_err(|error| format!("jlevere reverse: {error}"))?;
            write(&args[4], &target)?;
            write(&args[5], &reverse)
        }
        command => {
            usage();
            Err(format!("unknown command: {command}"))
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}
