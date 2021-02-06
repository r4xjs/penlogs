use crate::parser::{Result, ParseError};

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug)]
pub struct NmapService {
    pub port: u32,
    pub state: String,
    pub proto: String,
    pub app_proto: String,
    pub banner: String,
}

impl NmapService {
    pub fn new() -> Self {
	Self {
	    port: 0,
	    state: "".into(),
	    proto: "".into(),
	    app_proto: "".into(),
	    banner: "".into(),
	}
    }
    pub fn port(mut self, port: u32) -> Self {self.port = port; self}
    pub fn state(mut self, state: String) -> Self {self.state = state; self}
    pub fn proto(mut self, proto: String) -> Self {self.proto = proto; self}
    pub fn banner(mut self, banner: String) -> Self {self.banner = banner; self}
    pub fn app_proto(mut self, app_proto: String) -> Self {self.app_proto = app_proto; self}
}


#[derive(Debug)]
pub struct NmapHost {
    pub ip: IpAddr,
    pub services: Vec<NmapService>,
}

impl NmapHost {
    pub fn new(ip: IpAddr) -> Self {
	Self {
	    ip: ip,
	    services: vec![],
	}
    }
}

/// Parse function for gnmap files
/// The resulting Nmap struct contains the data from the gnmap file as Rust types. 
/// Note that we do not care if the entries are uniq or sorted at this point. It is the callers 
/// responebility to sort and merge information as needed. This function is just a parser.
///
/// example run: "sudo nmap -Pn -n --top-ports 500 -sSCV -iL start.lst -oA sSCV-top-500 -vvv"
pub fn parse<P: AsRef<Path>>(logfile: P) -> Result<Vec<NmapHost>> {

    // open the file with BurReader to iter over lines
    let fd = File::open(&logfile)?;
    let reader = BufReader::new(fd);
    let mut ret: Vec<NmapHost> = Vec::new();

    for line in reader.lines() {
	// example:
	// Host: 149.28.231.149 (149.28.231.149.vultr.com)	Ports: 80/open/tcp//http//nginx 1.18.0 (Ubuntu)/, 135/filtered/tcp//msrpc///, 	Ignored State: closed (995)
	let line = line?;
	if !line.starts_with("Host: ") || line.contains("Status: Up"){
	    // skip all uninteresting lines
	    continue;
	}

	// first parse the host
	let mut toks = line.split(' ');
	let ip = match toks.nth(1) {
	    Some(ip) => ip,
	    None => return Err(ParseError::Gnmap(line)),
	};
	let ip = ip.parse()?;
	let mut nmap_entry = NmapHost::new(ip);

	// skipping to "Ports: XXX"
	let mut toks = line.split('\t');
	toks.next();

	// parse the services
	let services = match toks.next() {
	    Some(services) => services,
	    None => return Err(ParseError::Gnmap(line.into())),
	};
	let services = match services.strip_prefix("Ports: ") {
	    Some(s) => s,
	    None => return Err(ParseError::Gnmap(services.into())),
	};
	for service in services.split(',') {
	    let toks: Vec<&str> = service.trim().split('/').map(|x| x).collect();
	    if toks.len() != 8 {
		return Err(ParseError::Gnmap(format!("service split: {}", service)));
	    }
	    let mut ns = NmapService::new();
	    let port = toks[0].parse::<u32>()?;
	    ns = ns.port(port);
	    ns = ns.state(toks[1].into());
	    ns = ns.proto(toks[2].into());
	    ns = ns.app_proto(toks[4].into());
	    ns = ns.banner(toks[6].into());

	    nmap_entry.services.push(ns);
	}
	ret.push(nmap_entry);
    }

    Ok(ret)
}

pub fn is_gnmap_log<P: AsRef<Path>>(logfile: P) -> bool {
    if let Some(ext) = logfile.as_ref().extension() {
	if let Some(ext) = ext.to_str() {
	    return ext == "gnmap";
	}
    }
    false
}
