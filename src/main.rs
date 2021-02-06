use std::path::Path;
mod parser;

enum OutFmt {
    Csv,
    Json,
    Dot,
    Urls,
}


//dot -Tsvg  -ox.svg <(cargo run -- ./test-logs dot)
fn main() {
    let mut args = std::env::args();
    if args.len() != 3 {
	println!("Usage: {} <log-dir> <output-format>", args.nth(0).unwrap());
	println!("output-format = {{csv,json,dot,urls}}");
	return;
    }
    let logdir = std::env::args().nth(1).unwrap();
    let output_format = match std::env::args().nth(2).unwrap().as_str() {
	"csv" => OutFmt::Csv,
	"json" => OutFmt::Json,
	"dot" => OutFmt::Dot,
	"urls" => OutFmt::Urls,
	v => {
	    println!("Output format {} is not supported", v);
	    println!("Supported are: csv, json, dot and urls");
	    return;
	}
    };

    let logdir = Path::new(&logdir);
    let systems = match parser::Systems::parse(logdir) {
	Ok(v) => v,
	Err(e) => {
	    println!("{:#?}", e);
	    return;
	},
    };

    let output = match output_format {
	OutFmt::Csv => systems.to_csv(),
	OutFmt::Json => systems.to_json(),
	OutFmt::Dot => systems.to_dot(),
	OutFmt::Urls => systems.to_urls(),
    };

    println!("{}", output);
}
