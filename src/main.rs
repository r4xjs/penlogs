mod parser;

use std::fs::OpenOptions;
use std::path::Path;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::collections::{HashSet, HashMap};

use seahorse::{App, Context, Command, Flag, FlagType};

fn generate_lists(c: &Context, systems: &parser::Systems)
		  -> parser::Result<()> {

    let dst_string = match c.string_flag("dst"){
	Ok(v) => v,
	_ => return Err(parser::ParseError::Flag("--dst flag is not given".into())),
    };
    let dst_dir = Path::new(&dst_string);

    let mut http_lst = BufWriter::new(OpenOptions::new().write(true).create(true).open(dst_dir.join("http.lst"))?);
    let mut https_lst = BufWriter::new(OpenOptions::new().write(true).create(true).open(dst_dir.join("https.lst"))?);
    let mut web_lst = BufWriter::new(OpenOptions::new().write(true).create(true).open(dst_dir.join("web.lst"))?);
    let mut ipv4_lst = BufWriter::new(OpenOptions::new().write(true).create(true).open(dst_dir.join("ipv4.lst"))?);
    let mut ipv6_lst = BufWriter::new(OpenOptions::new().write(true).create(true).open(dst_dir.join("ipv6.lst"))?);
    let mut domain_lst = BufWriter::new(OpenOptions::new().write(true).create(true).open(dst_dir.join("domain.lst"))?);

    // http, https and web
    println!("gen http.lst\ngen https.lst\ngen web.lst");
    for url in &systems.to_urls() {
	if url.starts_with("https") {
	    https_lst.write(url.as_bytes())?;
	} else {
	    http_lst.write(url.as_bytes())?;
	}
	web_lst.write(url.as_bytes())?;
    }

    let mut domains: HashSet<&str> = HashSet::new();
    let mut ipv4: HashSet<&IpAddr> = HashSet::new();
    let mut ipv6: HashSet<&IpAddr> = HashSet::new();
    let mut ports: HashMap<u32, HashSet<&IpAddr>> = HashMap::new();

    for system in systems.entries.values() {
	if system.ipinfo.ip.is_ipv4() {
	    ipv4.insert(&system.ipinfo.ip);
	} else {
	    ipv6.insert(&system.ipinfo.ip);
	}
	for domain in &system.domains {
	    domains.insert(domain.name.as_str());
	}
	for service in &system.services {
	    if service.state == parser::ServiceState::Open {
		if !ports.contains_key(&service.port) {
		    ports.insert(service.port, HashSet::new());
		}
		ports.get_mut(&service.port).unwrap().insert(&system.ipinfo.ip);
	    }
	}
    }
    println!("gen domain.lst");
    for domain in &domains {
	domain_lst.write(domain.as_bytes())?;
	domain_lst.write(b"\n")?;
    }
    println!("gen ipv4.lst");
    for ip in &ipv4 {
	ipv4_lst.write(format!("{}\n", ip).as_bytes())?;
    }
    println!("gen ipv6.lst");
    for ip in &ipv6 {
	ipv6_lst.write(format!("{}\n", ip).as_bytes())?;
    }
    for (port, ips) in &ports {
	let port_string = format!("{}.lst", port);
	let mut port_x_lst = BufWriter::new(OpenOptions::new()
					    .write(true)
					    .create(true)
					    .open(dst_dir.join(&port_string))?);
	println!("gen {}", &port_string);
	for ip in ips {
	    port_x_lst.write(format!("{}\n", ip).as_bytes())?;
	}
    }


    Ok(())
}

fn run_merge_cmd(c: &Context) {
    let mut systems = parser::Systems::new();

    for dir in &c.args {
	let _  = match systems.parse(&Path::new(dir)) {
	    Ok(_) => (),
	    Err(e) => {
		println!("{:#?}", e);
		return;
	    }
	};
    }
    let output = match c.string_flag("fmt").unwrap_or("csv".into()).as_str() {
	"csv" => systems.to_csv(),
	"json" => systems.to_json(),
	"dot" => systems.to_dot(),
	"lists" => {
	    match generate_lists(c, &systems) {
		Ok(()) => "done".into(),
		Err(e) => {
		    println!("{:#?}", e);
		    return;
		},
	    }
	},
	_ => systems.to_csv(),
    };
    println!("{}", &output);
}

fn run_diff_cmd(c: &Context) {
    let mut systems_old = parser::Systems::new();
    let mut systems_new = parser::Systems::new();

    let mut parse_new = false;
    for dir in &c.args {
	if dir == "#vs#" {
	    parse_new = true;
	    continue;
	}
	if !parse_new {
	    match systems_old.parse(Path::new(dir)) {
		Ok(()) => (),
		Err(e) => {
		    println!("{:#?}", e);
		    return;
		},
	    };
	} else {
	    match systems_new.parse(Path::new(dir)) {
		Ok(()) => (),
		Err(e) => {
		    println!("{:#?}", e);
		    return;
		},
	    };

	}
    }

    let systems = match systems_old.diff(systems_new) {
	Ok(s) => s,
	Err(e) => {
	    println!("{:#?}", e);
	    return;
	}
    };
    let output = match c.string_flag("fmt").unwrap_or("csv".into()).as_str() {
	"csv" => systems.to_csv(),
	"json" => systems.to_json(),
	"dot" => systems.to_dot(),
	f => format!("unknown diff format {}", f).into(),
    };
    println!("{}", &output);
}

fn merge_cmd() -> Command {
    Command::new("merge")
	.description("merge mode")
	.usage("merge: [flags] dirs...")
	.flag(Flag::new("fmt", FlagType::String)
	      .description("select output format")
	      .alias("f"))
	.flag(Flag::new("dst", FlagType::String)
	      .description("output directory to write lists to")
	      .alias("d"))
	.action(run_merge_cmd)
}

fn diff_cmd() -> Command {
    Command::new("diff")
	.description("diff mode")
	.usage("diff: [flags] <old-dirs>... \"#vs#\" <new-dirs>...")
	.flag(Flag::new("fmt", FlagType::String)
	      .description("select output format")
	      .alias("f"))
	.action(run_diff_cmd)
}

//dot -Tsvg  -ox.svg <(cargo run -- merge dot --dirs test-logs test-logs2)
fn main() {
    let app = App::new("penlogs")
	.usage("penlogs command [flags] directories...")
	.command(merge_cmd())
	.command(diff_cmd());
    app.run(std::env::args().collect());
}
