extern crate hmac;
#[macro_use]
extern crate lazy_static;
extern crate nix;
extern crate regex;
extern crate serde;
extern crate sha2;
extern crate toml;
extern crate users;

extern crate postfix_policy;
use postfix_policy::{handle_connection, PolicyRequestHandler, PolicyResponse};

use hmac::{Hmac, Mac};
use nix::unistd::{setresgid, setresuid, Gid, Uid};
use regex::bytes::Regex;
use serde::Deserialize;
use sha2::Sha256;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{metadata, remove_file, set_permissions, File};
use std::io::BufReader;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::thread;

// TODO whiltelist / blacklist
// config with regex -> username mapping

use std::error::Error;
use std::io::prelude::*;

const CONFIG_FILE_DEFAULT: &str = "/etc/recipient_filter.toml";

#[derive(Deserialize, Clone)]
struct Config {
    secret: String,
    min_length: usize,
    socket_path: String,
    user: String,
    group: String,
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
        lazy_static! {
            static ref MAIL_REGEX: Regex = Regex::new(r"^([^@]+)\.([a-f0-9]+)@.+$").expect("MAIL_REGEX invalid");
        }

        let mail_match = match MAIL_REGEX.captures(recipient) {
            Some(m) => m,
            None => {
                println!("Recipient does not match MAIL_REGEX: {:?}", recipient);
                self.response = Some(PolicyResponse::Dunno);
                return;
            }
        };

        let recipient_name = mail_match.get(1).expect("MAIL_REGEX has two groups").as_bytes();
        let recipient_hash = mail_match.get(2).expect("MAIL_REGEX has two groups").as_bytes();
        if recipient_hash.len() < self.config.min_length {
            println!("Checking Recipient {:?}: Hash too short!", recipient);
            self.response = Some(PolicyResponse::Dunno);
            return;
        }

        let expected_hash = compute_hash(recipient_name, &self.config.secret.as_bytes());
        if recipient_hash[0..self.config.min_length] != expected_hash[0..self.config.min_length] {
            println!("Checking Recipient {:?}: Wrong hash value!", recipient);
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
    let config = Config {
        secret: String::from("asdf"),
        socket_path: Default::default(),
        min_length: 6,
        user: Default::default(),
        group: Default::default(),
    };

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
    let config: Config = toml::from_str(&config_contents).expect("Error reading config file");

    let uid = Uid::from_raw(users::get_user_by_name(&config.user).expect("Invalid User").uid());
    let gid = Gid::from_raw(users::get_group_by_name(&config.group).expect("Invalid Group").gid());

    let socket_path = &config.socket_path;
    if let Ok(meta) = metadata(socket_path) {
        if meta.file_type().is_socket() {
            remove_file(socket_path)?;
        }
    }

    let listener = UnixListener::bind(socket_path).expect("Could not bind UNIX socket");
    set_permissions(socket_path, PermissionsExt::from_mode(0o666))?;
    setresgid(gid, gid, gid)?;
    setresuid(uid, uid, uid)?;

    for conn in listener.incoming() {
        let mut conn = conn?;
        let clone = conn.try_clone()?;
        let config = config.clone();
        thread::spawn(move || {
            let reader = BufReader::new(clone);
            if let Err(e) = handle_connection::<EmailValidator, _, _, _>(reader, &mut conn, &config) {
                println!("handle_connection failed: {:?}", e);
            };
        });
    }

    Ok(())
}
