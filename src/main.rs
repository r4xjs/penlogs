mod parser;
mod cli;

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::io::{BufWriter, Write};

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

    // write out http.lst, https.lst and web.lst
    let mut http_lst = BufWriter::new(OpenOptions::new()
	.write(true)
	.create(true)
	.open(dst_dir.join("http.lst"))?);
    let mut https_lst = BufWriter::new(OpenOptions::new()
	.write(true)
	.create(true)
	.open(dst_dir.join("https.lst"))?);
    let mut web_lst = BufWriter::new(OpenOptions::new()
	.write(true)
	.create(true)
	.open(dst_dir.join("web.lst"))?);

    for url in &systems.to_urls() {
	if url.starts_with("https") {
	    https_lst.write(url.as_bytes())?;
	} else {
	    http_lst.write(url.as_bytes())?;
	}
	web_lst.write(url.as_bytes())?;
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
	    "lists generated".into()
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
