// TODO improve log messages with utf8 conversions

extern crate hmac;
extern crate nix;
extern crate regex;
extern crate scoped_pool;
extern crate serde;
extern crate sha2;
extern crate toml;
extern crate users;

extern crate postfix_policy;
use postfix_policy::{handle_connection, PolicyRequestHandler, PolicyResponse};

use hmac::{Hmac, Mac};
use nix::unistd::{setresgid, setresuid, Gid, Uid};
use regex::bytes::{Regex, RegexSet};
use serde::Deserialize;
use sha2::Sha256;

use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{metadata, remove_file, set_permissions, File};
use std::io::prelude::*;
use std::io::BufReader;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;

const CONFIG_FILE_DEFAULT: &str = "/etc/recipient_filter.toml";

#[derive(Deserialize)]
struct ConfigFile {
    secret: Option<String>,
    min_length: usize,
    socket_path: String,
    user: String,
    group: String,
    whitelist: Option<Vec<String>>,
    blacklist: Option<Vec<String>>,
}

struct Config {
    secret: Vec<u8>,
    min_length: usize,
    socket_path: String,
    user: Uid,
    group: Gid,
    mail_regex: Regex,
    whitelist: RegexSet,
    blacklist: RegexSet,
}

impl Config {
    fn new() -> Self {
        Config {
            secret: vec![],
            min_length: 6,
            socket_path: Default::default(),
            user: Uid::from_raw(0),
            group: Gid::from_raw(0),
            mail_regex: Regex::new(r"^([^@]+)\.([a-f0-9]+)@.+$").expect("MAIL_REGEX invalid"),
            whitelist: RegexSet::new::<_, &String>(&[]).expect("empty RegexSet"),
            blacklist: RegexSet::new::<_, &String>(&[]).expect("empty RegexSet"),
        }
    }
    fn load(file_contents: ConfigFile) -> Option<Self> {
        let mut config = Self::new();

        config.secret = file_contents
            .secret
            .expect("Config File: Secret is missing")
            .into_bytes();
        config.min_length = file_contents.min_length;
        config.socket_path = file_contents.socket_path;
        config.user = Uid::from_raw(
            users::get_user_by_name(&file_contents.user)
                .expect("Invalid User")
                .uid(),
        );
        config.group = Gid::from_raw(
            users::get_group_by_name(&file_contents.group)
                .expect("Invalid Group")
                .gid(),
        );
        if let Some(whitelist) = file_contents.whitelist {
            config.whitelist = RegexSet::new(whitelist).expect("Invalid Whitelist Entry");
        }
        if let Some(blacklist) = file_contents.blacklist {
            config.blacklist = RegexSet::new(blacklist).expect("Invalid Blacklist Entry");
        }
        Some(config)
    }
}

fn compute_hash(msg: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut mac: Hmac<Sha256> = Hmac::new_varkey(secret).expect("The Secret is invalid");
    mac.input(msg);
    let code = mac.result().code();
    format!("{:x}", code).into_bytes()
}

#[test]
fn test_compute_hash() {
    let secret = b"asdf";
    let msg = b"test";

    assert_eq!(
        b"8338a5d6d429c4f6618e2e02e296e283570f46378bc7e2a8dbbb399599cf6096"[..],
        compute_hash(msg, secret)[..]
    );
}

struct EmailValidator<'l> {
    config: &'l Config,
    response: Option<PolicyResponse>,
}
impl<'l> EmailValidator<'l> {
    fn request(&mut self, policy: &[u8]) {
        if policy != b"smtpd_access_policy" {
            println!("Got unknown policy request: {:?}", policy);
            self.response = Some(PolicyResponse::Dunno);
        }
    }
    fn recipient(&mut self, recipient: &[u8]) {
        if self.config.whitelist.is_match(recipient) {
            println!("Recipient {}: Found in whitelist", String::from_utf8_lossy(recipient));
            self.response = Some(PolicyResponse::Ok);
            return;
        }

        if self.config.blacklist.is_match(recipient) {
            println!("Recipient {}: Found in blacklist", String::from_utf8_lossy(recipient));
            self.response = Some(PolicyResponse::Reject(Vec::new()));
            return;
        }

        let mail_match = match self.config.mail_regex.captures(recipient) {
            Some(m) => m,
            None => {
                println!("Recipient {}: does not match MAIL_REGEX", String::from_utf8_lossy(recipient));
                self.response = Some(PolicyResponse::Dunno);
                return;
            }
        };

        let recipient_name = mail_match.get(1).expect("MAIL_REGEX has two groups").as_bytes();
        let recipient_hash = mail_match.get(2).expect("MAIL_REGEX has two groups").as_bytes();
        if recipient_hash.len() < self.config.min_length {
            println!("Recipient {}: Hash too short!", String::from_utf8_lossy(recipient));
            self.response = Some(PolicyResponse::Dunno);
            return;
        }

        let expected_hash = compute_hash(recipient_name, &self.config.secret);
        if recipient_hash[0..self.config.min_length] != expected_hash[0..self.config.min_length] {
            println!("Recipient {}: Wrong hash value!", String::from_utf8_lossy(recipient));
            self.response = Some(PolicyResponse::Dunno);
            return;
        }

        self.response = Some(PolicyResponse::Ok)
    }
}
impl<'l> PolicyRequestHandler<'l, Config> for EmailValidator<'l> {
    fn new(cfg: &'l Config) -> Self {
        Self {
            config: cfg,
            response: None,
        }
    }
    fn parse_line(&mut self, name: &[u8], value: &[u8]) {
        if self.response.is_some() {
            return;
        }
        match name {
            b"request" => self.request(value),
            b"recipient" => self.recipient(value),
            _ => {}
        }
    }

    fn response(self) -> PolicyResponse {
        self.response.unwrap_or(PolicyResponse::Dunno)
    }
}

#[test]
fn test_handle_request() {
    let mut config = Config::new();
    config.secret = Vec::from("asdf");

    let mut ctx = EmailValidator::new(&config);
    ctx.parse_line(b"request", b"smtpd_access_policy");
    ctx.parse_line(b"recipient", b"test.8338a5@some.where.net");
    assert_eq!(ctx.response(), PolicyResponse::Ok);

    let mut ctx = EmailValidator::new(&config);
    ctx.parse_line(b"request", b"smtpd_access_policy");
    ctx.parse_line(b"recipient", b"test.aaaaaa@some.where.net");
    assert_eq!(ctx.response(), PolicyResponse::Dunno);

    let mut ctx = EmailValidator::new(&config);
    ctx.parse_line(b"request", b"smtpd_access_policy");
    ctx.parse_line(b"recipient", b"test@some.where.net");
    assert_eq!(ctx.response(), PolicyResponse::Dunno);

    let mut ctx = EmailValidator::new(&config);
    ctx.parse_line(b"request", b"smtpd_access_policy");
    ctx.parse_line(b"recipient", b"test.8338a@some.where.net");
    assert_eq!(ctx.response(), PolicyResponse::Dunno);

    config.whitelist = RegexSet::new(&[".+@some.where.net$"]).unwrap();
    config.blacklist = RegexSet::new(&[".+@not.to.here.net$"]).unwrap();
    let mut ctx = EmailValidator::new(&config);
    ctx.parse_line(b"request", b"smtpd_access_policy");
    ctx.parse_line(b"recipient", b"test@some.where.net");
    assert_eq!(ctx.response(), PolicyResponse::Ok);

    let mut ctx = EmailValidator::new(&config);
    ctx.parse_line(b"request", b"smtpd_access_policy");
    ctx.parse_line(b"recipient", b"test.8338a@some.where.other.net");
    assert_eq!(ctx.response(), PolicyResponse::Dunno);

    let mut ctx = EmailValidator::new(&config);
    ctx.parse_line(b"request", b"smtpd_access_policy");
    ctx.parse_line(b"recipient", b"test.8338a5@not.to.here.net");
    assert_eq!(ctx.response(), PolicyResponse::Reject);
}

fn main() -> Result<(), Box<Error>> {
    let args: Vec<OsString> = env::args_os().collect();
    let config_path = match args.get(1) {
        Some(p) => p,
        None => OsStr::new(CONFIG_FILE_DEFAULT),
    };

    if config_path == "-h" || config_path == "--help" {
        println!("Usage: {} [<config_file>]", args[0].to_string_lossy());
        return Ok(());
    }

    let mut config_contents = String::new();
    File::open(config_path)
        .expect("Config file missing")
        .read_to_string(&mut config_contents)
        .expect("Error reading config file");
    let config_file: ConfigFile = toml::from_str(&config_contents).expect("Error reading config file");
    let config = match Config::load(config_file) {
        None => return Ok(()),
        Some(c) => c,
    };

    let socket_path = &config.socket_path;
    if let Ok(meta) = metadata(socket_path) {
        if meta.file_type().is_socket() {
            remove_file(socket_path)?;
        }
    }

    let listener = UnixListener::bind(socket_path).expect("Could not bind UNIX socket");
    set_permissions(socket_path, PermissionsExt::from_mode(0o666))?;
    setresgid(config.group, config.group, config.group)?;
    setresuid(config.user, config.user, config.user)?;

    let thread_pool = scoped_pool::Pool::new(4);
    thread_pool.scoped::<_, Result<(), Box<Error>>>(|scope| {
        for conn in listener.incoming() {
            let mut conn = conn?;
            let clone = conn.try_clone()?;
            let cfg_ref = &config;
            scope.execute(move || {
                let reader = BufReader::new(clone);
                if let Err(e) = handle_connection::<EmailValidator, _, _, _>(reader, &mut conn, cfg_ref) {
                    println!("handle_connection failed: {:?}", e);
                };
            });
        }

        Ok(())
    })?;

    Ok(())
}
