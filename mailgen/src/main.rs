extern crate clap;
extern crate dirs;
extern crate hmac;
extern crate sha2;
extern crate toml;

use clap::{App, AppSettings, Arg};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::boxed::Box;
use std::error::Error;
use std::fs::File;
use std::io::ErrorKind as IoErrorKind;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::from_utf8;

const CONFIG_FILE_NAME: &str = "config.toml";

fn compute_hash(msg: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut mac: Hmac<Sha256> = Hmac::new_varkey(secret).expect("The Secret is invalid");
    mac.input(msg);
    let code = mac.result().code();
    format!("{:x}", code).into_bytes()
}

#[derive(Serialize, Deserialize, Default)]
struct Config {
    secret: String,
    length: usize,
    domain: String,
}

fn main() -> Result<(), Box<Error>> {
    let default_config_path = dirs::config_dir()
        .expect("Could not find XDG_CONFIG_HOME")
        .join(env!("CARGO_PKG_NAME"))
        .join(CONFIG_FILE_NAME);

    let args = App::new(env!("CARGO_PKG_NAME"))
        .about("Generate new email addresses with a secret that will be valid for the recipient_filter.")
        .setting(AppSettings::UnifiedHelpMessage)
        .author(env!("CARGO_PKG_AUTHORS"))
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("SECRET")
                .long("secret")
                .short("s")
                .takes_value(true)
                .help("Set the secret to SECRET"),
        )
        .arg(
            Arg::with_name("LENGTH")
                .long("length")
                .short("l")
                .takes_value(true)
                .help("Set the hash length to LENGTH"),
        )
        .arg(
            Arg::with_name("DOMAIN")
                .long("domain")
                .short("d")
                .takes_value(true)
                .help("Set the mail domain to DOMAIN"),
        )
        .arg(
            Arg::with_name("save")
                .long("save")
                .help("Save current values in the config file"),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .value_name("FILE")
                .default_value_os(default_config_path.as_os_str())
                .required(false)
                .help("Use this config file"),
        )
        .arg(
            Arg::with_name("NAME")
                .index(1)
                .multiple(true)
                .help("Generate a valid email for NAME"),
        )
        .get_matches();

    let config_path = PathBuf::from(args.value_of_os("config").expect("config has a default value"));
    if let Some(config_dir) = config_path.parent() {
        std::fs::create_dir_all(config_dir)?;
    }

    let mut config: Config = Default::default();
    match File::open(&config_path) {
        Ok(mut config_file) => {
            let mut file_contents = Vec::new();
            config_file.read_to_end(&mut file_contents)?;
            config = toml::from_slice(&file_contents)?;
        }
        Err(e) => {
            if e.kind() != IoErrorKind::NotFound || config_path != default_config_path {
                return Err(Box::from(e));
            }
        }
    }

    if let Some(secret) = args.value_of("SECRET") {
        config.secret = String::from(secret);
    }
    if let Some(len) = args.value_of("LENGTH") {
        config.length = len.parse()?;
    }
    if let Some(domain) = args.value_of("DOMAIN") {
        config.domain = String::from(domain);
    }

    if args.is_present("save") {
        let data = toml::to_vec(&config)?;
        File::create(&config_path)?.write_all(&data)?;
        println!("Saved config file to {}", config_path.as_os_str().to_string_lossy());
    }

    if config.secret.len() == 0 {
        println!("No secret given!");
        return Ok(());
    }

    for name in args.values_of("NAME").expect("NAME is an argument") {
        let name = name.to_ascii_lowercase();
        let hash = compute_hash(name.as_bytes(), &config.secret.as_bytes());
        let hash = from_utf8(&hash[0..config.length])?;
        println!("{}.{}@{}", name, hash, &config.domain);
    }

    Ok(())
}
