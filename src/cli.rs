#[derive(Debug,PartialEq)]
pub enum OutFmt {
    Csv,
    Json,
    Dot,
    Urls,
}
#[derive(Debug,PartialEq)]
pub enum Cmd {
    Merge,
    Diff,
}

#[derive(Debug,PartialEq)]
pub enum Flag {
    New(Vec<String>),
    Old(Vec<String>),
    Dirs(Vec<String>),
    None,
}

#[derive(Debug)]
pub struct CliArgs {
    pub cmd: Cmd,
    pub fmt: OutFmt,
    pub flags: Vec<Flag>,
}

impl CliArgs {
    pub fn parse<I: Iterator<Item=String>>(args: &mut I) -> Result<Self, String> {

	// skip frist element (binary name)
	let _ = args.next();
	
	// first parse the Command
	let cmd_string = args.next().ok_or("No command given")?;
	let cmd = match cmd_string.as_str() {
	    "merge" => Cmd::Merge,
	    "diff" => Cmd::Diff,
	    v => return Err(format!("Unknown command: {}", v)),
	};

	// parse the output format next
	let fmt_string = args.next().ok_or("No output format given")?;
	let fmt = match fmt_string.as_str() {
	    "csv" => OutFmt::Csv,
	    "json" => OutFmt::Json,
	    "dot" => OutFmt::Dot,
	    "urls" => OutFmt::Urls,
	    v => return Err(format!("Unknown output format: {}", v)),
	};

	// create initial return struct
	let mut ret = Self {
	    cmd: cmd,
	    fmt: fmt,
	    flags: Vec::new(),
	};

	// parse the rest of the flags/args
	let mut current_flag = Flag::None;
	for arg in args {
	    if arg.starts_with("--") {
		if current_flag != Flag::None {
		    // we are starting a new flag // save the old flag to the struct
		    ret.flags.push(current_flag);
		}
		// its a flag
		current_flag = match arg.as_ref() {
		    "--dirs" => {
			if ret.cmd == Cmd::Diff {
			    return Err("diff command needs --new and --old flags and not --dirs".into());
			}
			Flag::Dirs(Vec::new())
		    },
		    "--new" => {
			if ret.cmd != Cmd::Diff {
			    return Err("flag --new is only supported for the diff command".into());
			}
			Flag::New(Vec::new())
		    },
		    "--old" => {
			if ret.cmd != Cmd::Diff {
			    return Err("flag --old is only supported for the diff command".into());
			}
			Flag::Old(Vec::new())
		    },
		    v => return Err(format!("Unkown flag: {}", v).into()),
		};
		continue;
	    }

	    // parse the list of directories for the current_flag 
	    let _ = match current_flag {
		Flag::Dirs(ref mut v) => {
		    v.push(arg);
		},
		Flag::Old(ref mut v) | Flag::New(ref mut v) => {

		    v.push(arg);
		},
		Flag::None => return Err("need a flag first".into()),
	    };
	}

	// last flag is pushed here, the other flags are pushed when a new flag is started
	ret.flags.push(current_flag);

	Ok(ret)
    }

}







