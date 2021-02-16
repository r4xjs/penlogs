mod parser;
mod cli;

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::collections::{HashSet, HashMap};

fn generate_lists(args: &cli::CliArgs, systems: &parser::Systems)
		  -> parser::Result<()> {

    // TODO: need to change the args.flags data structure, this is painful
    let mut dst_dir: Option<PathBuf> = None;
    for flag in &args.flags {
	if let cli::Flag::Dst(v) = flag {
	    dst_dir = Some(v.to_path_buf());
	    break;
	}
    }
    let dst_dir = match dst_dir {
	Some(v) => v,
	None => return Err(parser::ParseError::FileNotFound(
	    "--dst directory not given".into())),
    };

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

fn run_merge_cmd(args: &cli::CliArgs) -> parser::Result<()> {
    let mut systems = parser::Systems::new();
    for flag in &args.flags {
	if let cli::Flag::Dirs(dirs) = flag {
	    for dir in dirs {
		systems.parse(dir)?;
	    }
	}
    }
    let output = match args.fmt {
	cli::OutFmt::Csv => systems.to_csv(),
	cli::OutFmt::Json => systems.to_json(),
	cli::OutFmt::Dot => systems.to_dot(),
	cli::OutFmt::Urls => systems.to_urls()
	    .iter()
	    .map(|v| v.to_string())
	    .collect(),
	cli::OutFmt::Lists => {
	    generate_lists(&args, &systems)?;
	    "done".into()
	},
    };
    println!("{}", &output);
    Ok(())
}

fn run_diff_cmd(args: &cli::CliArgs) -> parser::Result<()> {
    let mut systems_old = parser::Systems::new();
    let mut systems_new = parser::Systems::new();
    for flag in &args.flags {
	if let cli::Flag::Old(dirs) = flag {
	    for dir in dirs {
		systems_old.parse(dir)?;
	    }
	}
	if let cli::Flag::New(dirs) = flag {
	    for dir in dirs {
		systems_new.parse(dir)?;
	    }
	}
    }
    let systems = systems_old.diff(systems_new)?;
    let output = match args.fmt {
	cli::OutFmt::Csv => systems.to_csv(),
	cli::OutFmt::Json => systems.to_json(),
	cli::OutFmt::Dot => systems.to_dot(),
	cli::OutFmt::Urls => systems.to_urls()
	    .iter()
	    .map(|v| v.to_string())
	    .collect(),
	cli::OutFmt::Lists => unreachable!(), 
    };
    println!("{}", &output);
    Ok(())
}

fn usage() {
    println!("Usage: {} <cmd> <format> <flags>",
		std::env::args().nth(0).unwrap());
    println!("\tcmd    = {{merge, diff}}");
    println!("\tformat = {{csv, json, dot, urls, lists}}");
    println!("\tflags  = {{--dirs, --new, --old, --dst}}");
    println!("\t         receceives one or more directory as argument");
}

//dot -Tsvg  -ox.svg <(cargo run -- merge dot --dirs test-logs test-logs2)
fn main() {
    let mut args = std::env::args();
    let args = match cli::CliArgs::parse(&mut args) {
	Ok(v) => v,
	Err(e) => {
	    println!("{:#?}", e);
	    usage();
	    return;
	},
    };
    let ret = match args.cmd {
	cli::Cmd::Merge => run_merge_cmd(&args),
	cli::Cmd::Diff  => run_diff_cmd(&args),
    };

    match ret {
	Ok(_) => return,
	Err(e) => {
	    println!("{:?}", e);
	    return;
	},
    }
}
