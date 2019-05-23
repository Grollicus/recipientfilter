extern crate hmac;
#[macro_use]
extern crate lazy_static;
extern crate nix;
extern crate regex;
extern crate toml;
extern crate serde;
extern crate sha2;
extern crate users;

use regex::{Regex};
use serde::Deserialize;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use nix::unistd::{Uid, Gid, setresgid, setresuid};

use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::io::{BufReader};
use std::fs::{metadata, remove_file, File, set_permissions};
use std::collections::HashMap;
use std::env;
use std::ffi::{OsString, OsStr};

// TODO whiltelist / blacklist
// TODO process a Read / Write, not a UnixStream
// TODO use bytes
// make PolicyContext an Interface & library
// config with regex -> username mapping

use std::error::Error;
use std::io::prelude::*;

const CONFIG_FILE_DEFAULT: &str = "/etc/recipient_filter.toml";

#[derive(Deserialize)]
struct Config {
    secret: String,
    min_length: usize,
    socket_path: String,
    user: String,
    group: String,
}

fn compute_hash(msg: &str, secret: &str) -> String {
    let mut mac: Hmac<Sha256> = Hmac::new_varkey(secret.as_bytes()).expect("The Secret is invalid");
    mac.input(msg.as_bytes());
    let code = mac.result().code();
    format!("{:x}", code)
}

#[test]
fn test_compute_hash() {
    let secret = "asdf";
    let msg = "test";

    assert_eq!("8338a5d6d429c4f6618e2e02e296e283570f46378bc7e2a8dbbb399599cf6096", compute_hash(msg, secret));
}

struct PolicyContext {
    attributes: HashMap<String, String>
}

impl PolicyContext {
    fn new() -> Self {
        PolicyContext {
            attributes: HashMap::new()
        }
    }

    fn parse_line(&mut self, key: &str, value: &str) {
        self.attributes.insert(String::from(key.clone()), String::from(value.clone()));
    }
}

/*
request=smtpd_access_policy
protocol_state=RCPT
protocol_name=ESMTP
client_address=131.234.189.14
client_name=telepax.uni-paderborn.de
client_port=43528
reverse_client_name=telepax.uni-paderborn.de
server_address=12.34.56.78
server_port=25
helo_name=telepax.uni-paderborn.de
sender=foo@some.where.de
recipient=test@here.net
recipient_count=0
queue_id=
instance=3973.5ce5b0dd.81ed6.0
size=2004
etrn_domain=
stress=
sasl_method=
sasl_username=
sasl_sender=
ccert_subject=
ccert_issuer=
ccert_fingerprint=
ccert_pubkey_fingerprint=
encryption_protocol=
encryption_cipher=
encryption_keysize=0
policy_context=

*/


fn handle_request(ctx: PolicyContext, config: &Config) -> String {
    lazy_static! {
        static ref MAIL_REGEX: Regex = Regex::new(r"^([^@]+)\.([a-f0-9]+)@.+$").expect("MAIL_REGEX invalid");
    }
    println!("Got Request {}", ctx.attributes.get("request").unwrap_or(&String::from("<MISSING>")));
    let recipient = match ctx.attributes.get("recipient") {
        Some(rcp) => rcp,
        None => {
            println!("Recipient missing");
            return String::from("DUNNO")
        }
    };
    let mail_match = match MAIL_REGEX.captures(recipient) {
        Some(m) => m,
        None => {
            println!("Recipient does not match MAIL_REGEX: {:?}", recipient);
            return String::from("DUNNO");
        }
    };

    let recipient_name = mail_match.get(1).expect("MAIL_REGEX has two groups").as_str();
    let recipient_hash = mail_match.get(2).expect("MAIL_REGEX has two groups").as_str();
    if recipient_hash.len() < config.min_length {
        println!("Checking Recipient {}: Hash too short!", recipient);
        return String::from("DUNNO")
    }

    let expected_hash = compute_hash(recipient_name, &config.secret);
    if recipient_hash[0..config.min_length] != expected_hash[0..config.min_length] {
        println!("Checking Recipient {}: Wrong hash value!", recipient);
        return String::from("DUNNO")
    }

    String::from("OK")
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

    let mut ctx = PolicyContext::new();
    ctx.parse_line("request", "smtpd_access_policy");
    ctx.parse_line("recipient", "test.8338a5@some.where.net");
    assert_eq!(handle_request(ctx, &config), "OK");

    let mut ctx = PolicyContext::new();
    ctx.parse_line("request", "smtpd_access_policy");
    ctx.parse_line("recipient", "test.aaaaaa@some.where.net");
    assert_eq!(handle_request(ctx, &config), "DUNNO");

    let mut ctx = PolicyContext::new();
    ctx.parse_line("request", "smtpd_access_policy");
    ctx.parse_line("recipient", "test@some.where.net");
    assert_eq!(handle_request(ctx, &config), "DUNNO");

    let mut ctx = PolicyContext::new();
    ctx.parse_line("request", "smtpd_access_policy");
    ctx.parse_line("recipient", "test.8338a@some.where.net");
    assert_eq!(handle_request(ctx, &config), "DUNNO");
}


fn handle_connection(conn: UnixStream, config: &Config) -> Result<(), Box<Error>> {
    let mut read = BufReader::new(&conn);
    let mut ctx = PolicyContext::new();

    loop {
        let mut resp = String::new();
        if read.read_line(&mut resp)? == 0 {
            return Ok(())
        }

        if resp == "\n" {
            let action = handle_request(ctx, config);
            writeln!(&conn, "action={}\n", action)?;
            ctx = PolicyContext::new();
            continue;
        }

        match resp.find('=') {
            None => {
                println!("Read invalid line, ignoring: {:?}", resp);
                continue;
            },
            Some(pos) => {
                let (left, mut right) = resp.split_at(pos);
                if right.len() < 2 {
                    println!("Read invalid line, ignoring: {:?}", resp);
                    continue;
                }
                right = &right[1..right.len()-1];
                ctx.parse_line(left, right);
            }
        }
    }
}


fn main() -> Result<(), Box<Error>> {

    let args: Vec<OsString> = env::args_os().collect();
    let config_path = match args.get(1) {
        Some(p) => p,
        None => OsStr::new(CONFIG_FILE_DEFAULT),
    };

    if config_path == "-h" || config_path == "--help" {
        println!("Usage: {} [<config_file>]", args.get(0).unwrap().to_string_lossy());
        return Ok(())
    }

    let mut config_contents = String::new();
    File::open(config_path).expect("Config file missing").read_to_string(&mut config_contents).expect("Error reading config file");
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
        let conn = conn?;
        if let Err(e) = handle_connection(conn, &config) {
            println!("Error in connection handler: {:?}", e);
        }
    }

    Ok(())
}
