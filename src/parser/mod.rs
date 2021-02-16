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
pub type Result<T> = std::result::Result<T, ParseError>;
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


#[derive(Debug,Deserialize,Serialize,Clone,PartialEq,Eq,Hash)]
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

#[derive(Debug,Deserialize,Serialize,Clone,PartialEq,Eq,Hash)]
pub enum DiffState {
    Deleted,
    New,
    UpdatedNew,
    UpdatedOld,
    None,
}
impl DiffState {
    pub fn to_string(&self) -> String {
	use DiffState::*;
	match self {
	    Deleted => "Deleted".into(),
	    New => "New".into(),
	    UpdatedNew => "UpdatedNew".into(),
	    UpdatedOld => "UpdatedOld".into(),
	    None => "".into(),
	}
    }
}


#[derive(Debug,Deserialize,Serialize)]
pub struct System {
    pub ipinfo: IpInfo,
    pub domains: HashSet<Domain>,
    pub services: HashSet<Service>, 
    pub diff_state: DiffState,
}
impl System {
    pub fn new(ip: IpInfo) -> Self {
	Self {
	    ipinfo: ip,
	    domains: HashSet::new(),
	    services: HashSet::new(),
	    diff_state: DiffState::None,
	}
    }
}

#[derive(Debug,Deserialize,Serialize,Clone,PartialEq,Eq,Hash)]
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
    pub fn update(&mut self, other: Self) {
	if self.ip != other.ip {
	    return;
	}
	if self.cidr.is_empty() && !other.cidr.is_empty() {
	    self.cidr = other.cidr;
	}
	if self.desc.is_empty() && !other.desc.is_empty() {
	    self.desc = other.desc;
	}
	if self.asn == 0 {
	    self.asn = other.asn;
	}
    }
}


#[derive(Debug,Deserialize,Serialize,Clone,PartialEq,Eq,Hash)]
pub struct Domain {
    pub name: String,
    pub diff_state: DiffState,
}
impl Domain {
    pub fn new(domain: &str) -> Self {
	Self {
	    name: domain.into(),
	    diff_state: DiffState::None,
	}
	    
    }
}

#[derive(Debug,Deserialize,Serialize,Clone,PartialEq,Eq,Hash)]
pub struct Service {
    pub port: u32,
    pub state: ServiceState,
    pub proto: String,
    pub app_proto: String,
    pub banner: String,
    pub diff_state: DiffState,
}
impl Service {
    pub fn new(port: u32, state: &str, proto: &str, app_proto: &str, banner: &str) -> Self {
	Self {
	    port: port,
	    state: ServiceState::from_str(state),
	    proto: proto.into(),
	    app_proto: app_proto.into(),
	    banner: banner.into(),
	    diff_state: DiffState::None,
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
    pub entries: HashMap<IpAddr, System>,
    pub diffed: bool,
}

impl Systems {
    pub fn new() -> Systems {
	Self {
	    entries: HashMap::new(),
	    diffed: false,
	}
    }

    pub fn parse(&mut self, logdir: &Path) -> Result<()> {
	if !logdir.is_dir() {
	    return Err(ParseError::FileNotFound(format!("directory not found: {:?}", logdir).into()));
	}
	self.visit_dirs(logdir)?;
	Ok(())
    }

    pub fn diff(self, new: Self) -> Result<Self> {
	// TODO: do this better and faster later

	let mut ret = Self::new();

	// fill up IP sets
	let old_ips: HashSet<&IpInfo> = self.entries.values().map(|x| &x.ipinfo).collect();
	let new_ips: HashSet<&IpInfo> = new.entries.values().map(|x| &x.ipinfo).collect();

	// fill up domain sets
	fn merge_domains(systems: &Systems) -> HashSet<&Domain> {
	    let mut ret: HashSet<&Domain> = HashSet::new();
	    for (_, system) in &systems.entries {
		for domain in &system.domains {
		    ret.insert(domain);
		}
	    }
	    ret
	}
	let old_domains = merge_domains(&self);
	let new_domains = merge_domains(&new);

	// fill up Service sets
	fn merge_services(systems: &Systems) -> HashSet<&Service> {
	    let mut ret: HashSet<&Service> = HashSet::new();
	    for (_, system) in &systems.entries {
		for service in &system.services {
		    ret.insert(service);
		}
	    }
	    ret
	}
	let old_services = merge_services(&self);
	let new_services = merge_services(&new);

	// now that we have nice flat sets we create a new Systems struct
	// and set the diff_state depending on if old_x is in new_set and new_x is in old_set
	for old_ip in &old_ips {
	    let mut system = System::new((*old_ip).clone());

	    // diff ip
	    if !new_ips.iter().any(|x| x.ip == old_ip.ip) {
		system.diff_state = DiffState::Deleted;
	    }

	    // diff domains
	    let old_system = self.entries.get(&old_ip.ip).unwrap();
	    for old_domain in &old_system.domains {
		let mut domain = old_domain.clone();
		if !new_domains.contains(old_domain) {
		    domain.diff_state = DiffState::Deleted;
		}
		if new.entries.contains_key(&old_ip.ip) && 
		    !new.entries.get(&old_ip.ip).unwrap().domains.contains(old_domain) {
			domain.diff_state = DiffState::Deleted;
		}
		system.domains.insert(domain);
	    }

	    // diff services
	    for old_service in &old_system.services {
		let mut service = old_service.clone();
		if !new_services.contains(old_service) {
		    service.diff_state = DiffState::Deleted;
		}
		if new.entries.contains_key(&old_ip.ip) { 
		    let new_system_services = &new.entries.get(&old_ip.ip).unwrap().services;//.contains(old_service) 
		    if new_system_services.iter().any(|x|
					    x.port == old_service.port &&
					    x.state == old_service.state &&
					    x != old_service){
			// for example the banner just changed
			// but the port is still open
			service.diff_state = DiffState::UpdatedOld;
		    } else if !new_system_services.contains(old_service) {
			// the above special case is not true, so mark the rest as deleted
			service.diff_state = DiffState::Deleted;
		    }
		}

		system.services.insert(service);
	    }

	    ret.entries.insert(old_ip.ip, system);
	}

	for new_ip in &new_ips {
	    let system = match ret.entries.get_mut(&new_ip.ip) {
		Some(v) => v,
		None => {
		    let mut s = System::new((*new_ip).clone());
		    s.diff_state = DiffState::New;
		    ret.entries.insert(new_ip.ip, s);
		    ret.entries.get_mut(&new_ip.ip).unwrap()
		},
	    };

	    // diff domains
	    let new_system = new.entries.get(&new_ip.ip)
		.expect("new_ip not in new, should not happen");
	    for new_domain in &new_system.domains {
		let mut domain = new_domain.clone();
		if !old_domains.contains(new_domain) {
		    domain.diff_state = DiffState::New;
		}
		if self.entries.contains_key(&new_ip.ip) && 
		    !self.entries.get(&new_ip.ip).unwrap().domains.contains(new_domain) {
			// !old.domains.contains(new_domain)
			domain.diff_state = DiffState::New;
		}
		if !self.entries.contains_key(&new_ip.ip) {
		    // if we have a new ip we want the services to be marked as new 
		    domain.diff_state = DiffState::New;
		}


		system.domains.insert(domain);
	    }

	    // diff services
	    for new_service in &new_system.services {
		let mut service = new_service.clone();
		if !old_services.contains(new_service) {
		    service.diff_state = DiffState::New;
		}
		if self.entries.contains_key(&new_ip.ip) { 
		    let old_system_services = &self.entries.get(&new_ip.ip).unwrap().services;
		    if old_system_services.iter().any(|x|
					    x.port == new_service.port &&
					    x.state == new_service.state &&
					    x != new_service){
			// for example the banner just changed
			// but the port is still open
			service.diff_state = DiffState::UpdatedNew;
		    } else if !old_system_services.contains(new_service) {
			// the above special case is not true, so mark the rest as deleted
			service.diff_state = DiffState::New;
		    }
		}
		if !self.entries.contains_key(&new_ip.ip) {
		    // if we have a new ip we want the services to be marked as new 
		    service.diff_state = DiffState::New;
		}

		system.services.insert(service);
	    }
	}

	
	// we use this bool for later in the output methods to_XYZ()	
	// to switch formating
	ret.diffed = true;

	Ok(ret)
    }

    pub fn to_json(&self) -> String {
	match serde_json::to_string_pretty(self) {
	    Ok(v) => v,
	    Err(e) => panic!("serde_json Error: {:?}", e),
	}
    }

    pub fn to_csv(&self) -> String {
	fn diff_state_to_string(state: &DiffState, name: &str) -> String {
	    match *state {
		DiffState::New => format!("#{}-New", name).into(),
		DiffState::Deleted => format!("#{}-Deleted", name).into(),
		DiffState::UpdatedNew => format!("#{}-UpdatedNew", name).into(),
		DiffState::UpdatedOld => format!("#{}-UpdatedOld", name).into(),
		DiffState::None => "".into(),
	    }
	}
	let mut ret: Vec<String> = vec!["ip,domain,port,state,proto,app_proto,banner".into()];
	for entry in self.entries.values() {
	    let entry_diff_state = diff_state_to_string(&entry.diff_state, "IP");
	    if entry.domains.len() > 0 {
		for domain in &entry.domains {
		    let domain_diff_state = diff_state_to_string(&domain.diff_state, "Domain");
		    if entry.services.len() > 0 {
			for service in &entry.services {
			    let service_diff_state = diff_state_to_string(&service.diff_state, "Service");
			    ret.push(format!("{}{},{}{},{},{},{},{},{}{}",
					     entry.ipinfo.ip,
					     entry_diff_state,
					     domain.name,
					     domain_diff_state,
					     service.port,
					     service.state.to_string(),
					     service.proto,
					     service.app_proto,
					     service.banner,
					     service_diff_state).into());
			}
		    } else {
			ret.push(format!("{}{},{}{},,,,,",
					 entry.ipinfo.ip,
					 entry_diff_state,
					 domain.name,
					 domain_diff_state
			));
		    }
		}
	    } else if entry.services.len() > 0 {
		for service in &entry.services {
		    let service_diff_state = diff_state_to_string(&service.diff_state, "Service");
		    // no domain infos when we get to this branch
		    ret.push(format!("{}{},,{},{},{},{},{}{}",
				    entry.ipinfo.ip,
				    entry_diff_state,
				    service.port,
				    service.state.to_string(),
				    service.proto,
				    service.app_proto,
				    service.banner,
				    service_diff_state).into());
		    
		}
	    } else {
		ret.push(format!("{}{},,,,,,", entry.ipinfo.ip, entry_diff_state).into());
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

	const DIFF_RED: &str = "#FF3333";
	const DIFF_GREEN: &str = "#55FF00";
	const DIFF_GRAY: &str = "#8C8C8C";
	const DIFF_ORANGE: &str = "#E69900";

	fn diff_color(state: &DiffState) -> &'static str{
	    match *state {
		DiffState::Deleted => DIFF_RED,
		DiffState::New => DIFF_GREEN,
		DiffState::UpdatedNew => DIFF_ORANGE,
		DiffState::UpdatedOld => DIFF_ORANGE,
		DiffState::None => DIFF_GRAY,
	    }

	}

	#[derive(Debug,Hash,PartialEq,Eq)]
	struct DotService<'a>(Vec<&'a Service>);
	impl<'a> DotService<'a> {
	    fn new(services: &Vec<&'a Service>) -> Self {
		let mut s: Vec<&Service> = Vec::new();
		for service in services {
		    s.push(service);
		}
		Self(s)
	    }
	    fn label(&self) -> String {
		let mut ret: Vec<String> = Vec::new();
		for service in &self.0 {
		    ret.push(format!("{}: {}",
				     service.diff_state.to_string(),
				     service.label()));
		}
		ret.sort();
		format!("{}\\l", ret.join("\\l"))
	    }
	    fn diff_state(&'a self) -> &'a DiffState {
		&self.0[0].diff_state
	    }
	}

	let mut ret: Vec<String> = vec!["digraph Systems {".into()];
	ret.push("rankdir=LR".into());
	ret.push("node  [style=\"rounded,filled,bold\", shape=box, fontname=\"Arial\"];".into());

	// create uniq domain ids
	let mut domain_map: HashMap<&Domain, u32> = HashMap::new();
	let mut domain_id_counter = 0x80000000;
	for entry in self.entries.values() {
	    for domain in &entry.domains {
		if !domain_map.contains_key(&domain) {
		    domain_map.insert(domain, domain_id_counter);
		    domain_id_counter += 1;
		}
	    }
	}

	// create service_map and merge updated services in DotService structs
	let mut service_map: HashMap<DotService, u32> = HashMap::new();
	let mut service_id_counter = 0x00000000;
	for system in self.entries.values() {
	    let mut same_port_services: HashMap<&u32, Vec<&Service>> = HashMap::new();
	    for service in &system.services {

		if !same_port_services.contains_key(&service.port) {
		    let mut hs = Vec::new();
		    hs.push(service);
		    same_port_services.insert(&service.port, hs);
		    continue;
		}
		same_port_services.get_mut(&service.port).unwrap().push(service);
	    }
	    for same_port_service in same_port_services.values() {

		service_map.insert(DotService::new(same_port_service), service_id_counter);
		service_id_counter += 1;
	    }
	}

	if !self.diffed {
	    // normal mode

	    // ip nodes
	    for (ip, system) in &self.entries {
		ret.push(format!("\"{}\" [label=\"{}\", fillcolor=\"{}\"];", ip, system.ipinfo.label(), BLUE).into());
	    }

	    // domain nodes
	    for (domain, domain_id) in &domain_map {
		ret.push(format!("\"{}\" [label=\"{}\", fillcolor=\"{}\"];", domain_id, domain.name, YELLOW).into());
	    }

	    // sevice nodes
	    for (service, service_id) in &service_map {
		let mut color = GREEN;
		if service.label().contains(", filtered,") {
		    color = GRAY;
		}
		ret.push(format!("\"{}\" [label=\"{}\", fillcolor=\"{}\"];", service_id, service.label(), &color).into());
	    }
	} else {
	    // diff mode

	    // ip nodes
	    for (ip, system) in &self.entries {
		let color = diff_color(&system.diff_state);
		ret.push(format!("\"{}\" [label=\"{}\", fillcolor=\"{}\"];", ip, system.ipinfo.label(), color).into());
	    }

	    // domain nodes
	    for (domain, domain_id) in &domain_map {
		let color = diff_color(&domain.diff_state);
		ret.push(format!("\"{}\" [label=\"{}\", fillcolor=\"{}\"];", domain_id, domain.name, color).into());
	    }

	    // sevice nodes
	    for (service, service_id) in &service_map {
		let color = diff_color(&service.diff_state());
		ret.push(format!("\"{}\" [label=\"{}\", fillcolor=\"{}\"];", service_id, service.label(), color).into());
	    }

	}

	// add "domain -> ip" edges
	for (ip, entry) in &self.entries {
	    for domain in &entry.domains {
		ret.push(format!("\"{}\" -> \"{}\" [splines=ortho]", domain_map.get(&domain).unwrap(), ip).into());
	    }
	}

	// add "ip -> service" edges
	for (ip, entry) in &self.entries {
	    for service in &entry.services{
		let service_idx: &u32 = service_map
		    .iter()
		    .filter(|(dot_service, _)|
			     dot_service.0.contains(&service))
		    .map(|(_, idx)| idx)
		    .nth(0)
		    .expect("to_dot: service_map broken, no matching service found");
		
		ret.push(format!("\"{}\" -> \"{}\"", ip, service_idx).into());
	    }
	}

	ret.push("}".into());
	ret.join("\n")
    }

    pub fn to_urls(&self) -> HashSet<String> {
	let mut http = Vec::<u32>::new();
	let mut https = Vec::<u32>::new();
	let mut ret = HashSet::<String>::new();

	fn add_urls(system: &System, ports: &[u32], schema: &str) -> HashSet::<String> {
	    let mut ret = HashSet::<String>::new();
	    for port in ports {
		ret.insert(format!("{}://{}:{}\n", schema, system.ipinfo.ip, port));
		for domain in &system.domains {
		    ret.insert(format!("{}://{}:{}\n", schema, domain.name, port));
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
	ret
    }

    
    /// Merges infos from the tool parsers into System entries
    fn cb_handler(&mut self, entry: &DirEntry) -> Result<()> {
	if amass::is_amass_log(entry.path()) {
	    let res = amass::parse(entry.path())?;
	    // merge into &self
	    for amass_entry in res {
		for ipinfo in amass_entry.addresses {
		    let ip = ipinfo.ip;
		    if !self.entries.contains_key(&ipinfo.ip) {
			self.entries.insert(ipinfo.ip, System::new(ipinfo));
		    } else {
			// check if we can update infos
			let entry = &mut self.entries.get_mut(&ipinfo.ip).unwrap();
			entry.ipinfo.update(ipinfo);
		    }
		    let entry = &mut self.entries.get_mut(&ip).unwrap();
		    entry.domains.insert(Domain::new(&amass_entry.name));
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
