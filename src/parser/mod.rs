use serde::{Deserialize, Serialize};
use serde_json;

use std::net::{IpAddr, AddrParseError};
use std::path::Path;
use std::io;
use std::fs::{self, DirEntry};
use std::collections::{HashMap, HashSet};
use core::num::ParseIntError;


pub mod amass;
pub mod nmap;

#[derive(Debug)]
pub enum ParseError {
    Ip(AddrParseError),
    Json(serde_json::Error),
    Gnmap(String),
    FileNotFound(String),
    Io(io::Error),
    IntParse(ParseIntError),
}
type Result<T> = std::result::Result<T, ParseError>;
macro_rules! impl_from {
    ($orig:ty, $enum:ident) => {
	impl From<$orig> for ParseError {
	    fn from(error: $orig) -> Self {
		ParseError::$enum(error)
	    }
	}
    };
}
impl_from!(io::Error, Io);
impl_from!(serde_json::Error, Json);
impl_from!(AddrParseError, Ip);
impl_from!(ParseIntError, IntParse);


#[derive(Debug,Deserialize,Serialize,PartialEq,Eq,Hash)]
pub enum ServiceState {
    Close,
    Open,
    Filtered,
    Unknown(String),
}
impl ServiceState {
    pub fn from_str(state: &str) -> Self {
	use ServiceState::*;
	match state {
	    "close" => Close,
	    "open" => Open,
	    "filtered" => Filtered,
	    _ => Unknown(state.into()),
	}
    }
    pub fn to_string(&self) -> String {
	use ServiceState::*;
	match *self {
	    Close => "close".into(),
	    Open => "open".into(),
	    Filtered => "filtered".into(),
	    Unknown(ref v) => format!("unknown({})", v).into()
	}
    }
}

#[derive(Debug,Deserialize,Serialize)]
pub struct System {
    ipinfo: IpInfo,
    domains: HashSet<String>,
    services: HashSet<Service>, 
}
impl System {
    pub fn new(ip: IpInfo) -> Self {
	Self {
	    ipinfo: ip,
	    domains: HashSet::new(),
	    services: HashSet::new(),
	}
    }
}

#[derive(Debug,Deserialize,Serialize,Clone)]
pub struct IpInfo {
    pub ip: IpAddr,
    pub cidr: String,
    pub asn: u64,
    pub desc: String,
}
impl IpInfo {
    pub fn new(ip: IpAddr) -> Self {
	Self {
	    ip: ip,
	    cidr: "".into(),
	    asn: 0,
	    desc: "".into(),
	}
    }
    pub fn label(&self) -> String {
	format!("{},{}", self.ip, self.desc).into()
    }
    pub fn update(&mut self, other: &Self) {
	if self.ip != other.ip {
	    return;
	}
	if self.cidr.is_empty() && !other.cidr.is_empty() {
	    self.cidr = other.cidr.clone();
	}
	if self.desc.is_empty() && !other.desc.is_empty() {
	    self.desc = other.desc.clone();
	}
	if self.asn == 0 {
	    self.asn = other.asn;
	}
    }
}



#[derive(Debug,Deserialize,Serialize,PartialEq,Eq,Hash)]
pub struct Service {
    port: u32,
    state: ServiceState,
    proto: String,
    app_proto: String,
    banner: String,
}
impl Service {
    pub fn new(port: u32, state: &str, proto: &str, app_proto: &str, banner: &str) -> Self {
	Self {
	    port: port,
	    state: ServiceState::from_str(state),
	    proto: proto.into(),
	    app_proto: app_proto.into(),
	    banner: banner.into(),
	}
    }
    pub fn label(&self) -> String {
	format!("{}, {}, {}",
		self.port,
		self.state.to_string(),
		self.banner).into()
    }
}


#[derive(Debug,Deserialize,Serialize)]
pub struct Systems {
    entries: HashMap<IpAddr, System>,
}

impl Systems {
    pub fn parse(logdir: &Path) -> Result<Systems> {
	if !logdir.is_dir() {
	    return Err(ParseError::FileNotFound(format!("directory not found: {:?}", logdir).into()));
	}
	let mut systems = Self {
	    entries: HashMap::new(),
	};
	match systems.visit_dirs(&logdir) {
	    Ok(()) => Ok(systems),
	    Result::Err(e) => Err(e),
	}
    }

    pub fn to_json(&self) -> String {
	match serde_json::to_string_pretty(self) {
	    Ok(v) => v,
	    Err(e) => panic!("serde_json Error: {:?}", e),
	}
    }

    pub fn to_csv(&self) -> String {
	let mut ret: Vec<String> = vec!["ip,domain,port,state,proto,app_proto,banner".into()];
	for entry in self.entries.values() {
	    if entry.domains.len() > 0 {
		for domain in &entry.domains {
		    if entry.services.len() > 0 {
			for service in &entry.services {
			    ret.push(format!("{},{},{},{},{},{},{}",
					     entry.ipinfo.ip,
					     domain,
					     service.port,
					     service.state.to_string(),
					     service.proto,
					     service.app_proto,
					     service.banner).into());
			}
		    } else {
			ret.push(format!("{},{},,,,,", entry.ipinfo.ip, domain));
		    }
		}
	    } else if entry.services.len() > 0 {
		for service in &entry.services {
		    // no domain infos when we get to this branch
		    ret.push(format!("{},,{},{},{},{},{}",
				    entry.ipinfo.ip,
				    service.port,
				    service.state.to_string(),
				    service.proto,
				    service.app_proto,
				    service.banner).into());
		    
		}
	    } else {
		ret.push(format!("{},,,,,,", entry.ipinfo.ip).into());
	    }
	}
	ret.join("\n")
    }

    pub fn to_dot(&self) -> String {
	//const RED: &str = "#ffa0a0";
	const GREEN: &str = "#a0ffa0";
	const BLUE: &str = "#5EA4FF";
	const GRAY: &str = "#8697A3";
	const YELLOW: &str = "#FFFB82";

	let mut ret: Vec<String> = vec!["digraph Systems {".into()];
	ret.push("rankdir=LR".into());
	ret.push("node  [style=\"rounded,filled,bold\", shape=box, fontname=\"Arial\"];".into());

	// create uniq domain ids
	let mut domain_map: HashMap<String, u32> = HashMap::new();
	let mut domain_id_counter = 0x80000000;
	for entry in self.entries.values() {
	    for domain in &entry.domains {
		if !domain_map.contains_key(domain) {
		    domain_map.insert(domain.clone(), domain_id_counter);
		    domain_id_counter += 1;
		}
	    }
	}

	// create uniq service ids
	let mut service_map: HashMap<String, u32> = HashMap::new();
	let mut service_id_counter = 0x00000000;
	for entry in self.entries.values() {
	    for service in &entry.services {
		let service_label = service.label();
		if !service_map.contains_key(&service_label) {
		    service_map.insert(service_label, service_id_counter);
		    service_id_counter += 1;
		}
	    }
	}

	// ip nodes
	for (ip, system) in &self.entries {
	    ret.push(format!("\"{}\" [label=\"{}\", fillcolor=\"{}\"];", ip, system.ipinfo.label(), BLUE).into());
	}

	// domain nodes
	for (domain_label, domain_id) in &domain_map {
	    ret.push(format!("\"{}\" [label=\"{}\", fillcolor=\"{}\"];", domain_id, domain_label, YELLOW).into());
	}

	// sevice nodes
	for (service_label, service_id) in &service_map {
	    let mut color = GREEN;
	    if service_label.contains(", filtered,") {
		color = GRAY;
	    }
	    ret.push(format!("\"{}\" [label=\"{}\", fillcolor=\"{}\"];", service_id, service_label, &color).into());
	}

	// add "domain -> ip" edges
	for (ip, entry) in &self.entries {
	    for domain in &entry.domains {
		ret.push(format!("\"{}\" -> \"{}\" [splines=ortho]", domain_map.get(domain).unwrap(), ip).into());
	    }
	}

	// add "ip -> service" edges
	for (ip, entry) in &self.entries {
	    for service in &entry.services{
		ret.push(format!("\"{}\" -> \"{}\"", ip, service_map.get(&service.label()).unwrap()).into());
	    }
	}

	ret.push("}".into());
	ret.join("\n")
    }

    pub fn to_urls(&self) -> String {
	let mut http = Vec::<u32>::new();
	let mut https = Vec::<u32>::new();
	let mut ret = HashSet::<String>::new();

	fn add_urls(system: &System, ports: &[u32], schema: &str) -> HashSet::<String> {
	    let mut ret = HashSet::<String>::new();
	    for port in ports {
		ret.insert(format!("{}://{}:{}\n", schema, system.ipinfo.ip, port));
		for domain in &system.domains {
		    ret.insert(format!("{}://{}:{}\n", schema, domain, port));
		}
	    }
	    ret
	}

	for system in self.entries.values() {
	    http.clear();
	    https.clear();

	    // search for all ports that has http or https in app_proto
	    for service in &system.services {
		if service.app_proto.contains("http") &&
		    service.state == ServiceState::Open {
			if service.app_proto.contains("https") ||
			    service.app_proto.contains("ssl") {
				https.push(service.port);
			} else {
				http.push(service.port);
			}
		}

	    }
	    ret.extend(add_urls(&system, &http, "http"));
	    ret.extend(add_urls(&system, &https, "https"));
	}
	ret.iter().map(|s| s.to_string()).collect()
    }

    
    /// Merges infos from the tool parsers into System entries
    fn cb_handler(&mut self, entry: &DirEntry) -> Result<()> {
	if amass::is_amass_log(entry.path()) {
	    let res = amass::parse(entry.path())?;
	    // merge into &self
	    for amass_entry in res {
		for ipinfo in amass_entry.addresses {
		    if !self.entries.contains_key(&ipinfo.ip) {
			self.entries.insert(ipinfo.ip, System::new(ipinfo.clone()));
		    } else {
			// check if we can update infos
			let entry = &mut self.entries.get_mut(&ipinfo.ip).unwrap();
			entry.ipinfo.update(&ipinfo);
		    }
		    let entry = &mut self.entries.get_mut(&ipinfo.ip).unwrap();
		    entry.domains.insert(amass_entry.name.clone());
		}
	    }
	    //println!("{:#?}", &res);
	    return Ok(());
	}
	if nmap::is_gnmap_log(entry.path()) {
	    let nmap_hosts = nmap::parse(entry.path())?;
	    // merge into &self
	    for nmap_host in &nmap_hosts {
		if !self.entries.contains_key(&nmap_host.ip) {
		    // insert new entry into system entries
		    self.entries.insert(nmap_host.ip, System::new(IpInfo::new(nmap_host.ip)));
		}

		let entry = &mut self.entries.get_mut(&nmap_host.ip).unwrap();
		for ns in &nmap_host.services {
		    entry.services.insert(Service::new(ns.port, &ns.state, &ns.proto, &ns.app_proto, &ns.banner));
		}
	    }
	    //println!("{:#?}", &res);
	    return Ok(());
	}
	Ok(())
    }

    /// Recursive walk over all files under a directory and call cb_handler(filepath) to parse logfiles
    fn visit_dirs(&mut self, dir: &Path) -> Result<()> {
	if dir.is_dir() {
	    let dir_iter = fs::read_dir(dir)?;
	    for entry in dir_iter {
		let entry = entry?;
		let path = entry.path();
		if path.is_dir() {
		    self.visit_dirs(&path)?;
		} else {
		    self.cb_handler(&entry)?;
		}
	    }
	}
	Ok(())
    }

}
