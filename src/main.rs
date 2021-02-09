mod parser;
mod cli;

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
	cli::OutFmt::Urls => systems.to_urls(),
    };
    println!("{}", &output);
    Ok(())
}

fn run_diff_cmd(_args: &cli::CliArgs) -> parser::Result<()> {
    Ok(())
}


//dot -Tsvg  -ox.svg <(cargo run -- merge dot --dirs test-logs test-logs2)
fn main() {
    let mut args = std::env::args();
    let args = match cli::CliArgs::parse(&mut args) {
	Ok(v) => v,
	Err(e) => {
	    println!("{:#?}", e);
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
