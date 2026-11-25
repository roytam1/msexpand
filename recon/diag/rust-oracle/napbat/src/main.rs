use std::env;
use std::fs;
use std::process;

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        return Err("usage: msdelta-napbat <source> <delta> <output>".to_string());
    }
    let source = fs::read(&args[1]).map_err(|error| format!("read {}: {error}", args[1]))?;
    let delta = fs::read(&args[2]).map_err(|error| format!("read {}: {error}", args[2]))?;
    let output = msdelta::apply(&source, &delta).map_err(|error| error.to_string())?;
    fs::write(&args[3], output).map_err(|error| format!("write {}: {error}", args[3]))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}
