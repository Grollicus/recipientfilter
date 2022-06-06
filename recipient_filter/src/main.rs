/*
    recipient_filter - access policy server to validate receiver addresses
    Copyright (C) 2019 Grollicus

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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

use hmac::{Hmac, Mac, NewMac};
use nix::unistd::{setresgid, setresuid, Gid, Uid};
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::Deserialize;
use sha2::Sha256;

use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{create_dir_all, metadata, remove_file, set_permissions, File};
use std::io::prelude::*;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;

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
            min_length: 8,
            socket_path: Default::default(),
            user: Uid::from_raw(0),
            group: Gid::from_raw(0),
            mail_regex: RegexBuilder::new(r"^([^@]+)\.([a-fA-F0-9]+)@.+$")
                .unicode(false)
                .build()
                .expect("MAIL_REGEX invalid"),
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
            config.whitelist = RegexSetBuilder::new(whitelist)
                .unicode(false)
                .case_insensitive(true)
                .build()
                .expect("Invalid Whitelist Entry");
        }
        if let Some(blacklist) = file_contents.blacklist {
            config.blacklist = RegexSetBuilder::new(blacklist)
                .unicode(false)
                .case_insensitive(true)
                .build()
                .expect("Invalid Blacklist Entry");
        }
        Some(config)
    }
}

fn compute_hash(msg: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut mac: Hmac<Sha256> = Hmac::new_from_slice(secret).expect("The Secret is invalid");
    mac.update(msg);
    let code = mac.finalize();
    format!("{:x}", code.into_bytes()).into_bytes()
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
                println!(
                    "Recipient {}: does not match MAIL_REGEX",
                    String::from_utf8_lossy(recipient)
                );
                self.response = Some(PolicyResponse::Reject(Vec::new()));
                return;
            }
        };

        let recipient_name = mail_match.get(1).expect("MAIL_REGEX has two groups").as_bytes();
        let recipient_hash = mail_match.get(2).expect("MAIL_REGEX has two groups").as_bytes();
        if recipient_hash.len() < self.config.min_length {
            println!("Recipient {}: Hash too short!", String::from_utf8_lossy(recipient));
            self.response = Some(PolicyResponse::Reject(Vec::new()));
            return;
        }

        let expected_hash = compute_hash(recipient_name, &self.config.secret);
        if recipient_hash[0..self.config.min_length].to_ascii_lowercase()[..]
            != expected_hash[0..self.config.min_length]
        {
            println!("Recipient {}: Wrong hash value!", String::from_utf8_lossy(recipient));
            self.response = Some(PolicyResponse::Reject(Vec::new()));
            return;
        }

        self.response = Some(PolicyResponse::Ok)
    }
}
impl<'l> PolicyRequestHandler<'l, Config, ()> for EmailValidator<'l> {
    fn new(cfg: &'l Config) -> Self {
        Self {
            config: cfg,
            response: None,
        }
    }
    fn attribute(&mut self, name: &[u8], value: &[u8]) -> Option<()> {
        if self.response.is_some() {
            return None;
        }
        match name {
            b"request" => self.request(value),
            b"recipient" => self.recipient(value),
            _ => {}
        }
        None
    }

    fn response(self) -> Result<PolicyResponse, ()> {
        Ok(self.response.unwrap_or(PolicyResponse::Dunno))
    }
}

#[test]
fn test_handle_request() {
    use postfix_policy::test_helper::handle_connection_response;

    let config_file = ConfigFile {
        secret: Some(String::from("asdf")),
        min_length: 6,
        socket_path: String::from("/some/where"),
        user: users::get_current_username().unwrap().into_string().unwrap(),
        group: users::get_current_groupname().unwrap().into_string().unwrap(),
        whitelist: Some([String::from(".+@allowed.net$")].to_vec()),
        blacklist: Some([String::from(".+@not.allowed.net$")].to_vec()),
    };
    let config = Config::load(config_file).unwrap();

    // correct hash + parsing
    let input = b"request=smtpd_access_policy\nrecipient=test.8338a5@some.where.net\n\n";
    assert_eq!(
        handle_connection_response::<EmailValidator, _, _>(input, &config).unwrap(),
        b"action=OK\n\n"
    );

    // correct hash
    let mut ctx = EmailValidator::new(&config);
    ctx.attribute(b"request", b"smtpd_access_policy");
    ctx.attribute(b"recipient", b"test.8338a5@some.where.net");
    assert_eq!(ctx.response(), Ok(PolicyResponse::Ok));

    // correct hash but different case
    let mut ctx = EmailValidator::new(&config);
    ctx.attribute(b"request", b"smtpd_access_policy");
    ctx.attribute(b"recipient", b"test.8338A5@some.where.net");
    assert_eq!(ctx.response().unwrap(), PolicyResponse::Ok);

    // wrong hash
    let mut ctx = EmailValidator::new(&config);
    ctx.attribute(b"request", b"smtpd_access_policy");
    ctx.attribute(b"recipient", b"test.aaaaaa@some.where.net");
    assert_eq!(ctx.response().unwrap(), PolicyResponse::Reject(vec![]));

    // hash missing
    let mut ctx = EmailValidator::new(&config);
    ctx.attribute(b"request", b"smtpd_access_policy");
    ctx.attribute(b"recipient", b"test@some.where.net");
    assert_eq!(ctx.response().unwrap(), PolicyResponse::Reject(vec![]));

    // too short
    let mut ctx = EmailValidator::new(&config);
    ctx.attribute(b"request", b"smtpd_access_policy");
    ctx.attribute(b"recipient", b"test.8338a@some.where.net");
    assert_eq!(ctx.response().unwrap(), PolicyResponse::Reject(vec![]));

    // whitelisted
    let mut ctx = EmailValidator::new(&config);
    ctx.attribute(b"request", b"smtpd_access_policy");
    ctx.attribute(b"recipient", b"test@allowed.net");
    assert_eq!(ctx.response().unwrap(), PolicyResponse::Ok);

    // whitelisted but different case
    let mut ctx = EmailValidator::new(&config);
    ctx.attribute(b"request", b"smtpd_access_policy");
    ctx.attribute(b"recipient", b"test@AlloWed.net");
    assert_eq!(ctx.response().unwrap(), PolicyResponse::Ok);

    // blacklisted, even though valid hash
    let mut ctx = EmailValidator::new(&config);
    ctx.attribute(b"request", b"smtpd_access_policy");
    ctx.attribute(b"recipient", b"test.8338a5@not.allowed.net");
    assert_eq!(ctx.response().unwrap(), PolicyResponse::Reject(Vec::new()));

    // blacklisted but different case, even though valid hash
    let mut ctx = EmailValidator::new(&config);
    ctx.attribute(b"request", b"smtpd_access_policy");
    ctx.attribute(b"recipient", b"test.8338a5@NOT.ALLOWED.net");
    assert_eq!(ctx.response().unwrap(), PolicyResponse::Reject(Vec::new()));
}

fn main() -> Result<(), Box<dyn Error>> {
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
    if let Some(socket_dir) = Path::new(socket_path).parent() {
        create_dir_all(socket_dir)?;
    }
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
    thread_pool.scoped::<_, Result<(), Box<dyn Error>>>(|scope| {
        for conn in listener.incoming() {
            let mut conn = conn?;
            let cfg_ref = &config;
            scope.execute(move || {
                if let Err(e) = handle_connection::<EmailValidator, _, _, _>(&mut conn, cfg_ref) {
                    println!("handle_connection failed: {:?}", e);
                };
            });
        }

        Ok(())
    })?;

    Ok(())
}
