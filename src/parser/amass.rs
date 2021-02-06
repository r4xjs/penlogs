use serde::{Deserialize, Serialize};
use serde_json;

use crate::parser::{Result, IpInfo};

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;


/// amass entry struct for serde_json
#[derive(Debug,Deserialize,Serialize)]
pub struct AmassEntry {
    pub name: String,
    pub domain: String,
    pub addresses: Vec<IpInfo>,
}


/// parse function for amass json file
/// The resulting Amass struct contains the data from the json file as Rust types parsed by serde_json. 
/// Note that we do not care if the entries are uniq or sorted at this point. It is the callers 
/// responebility to sort and merge information as needed. This function is just a parser.
///
/// example run: "amass enum -d 4chan.org -oA domains"
pub fn parse<P: AsRef<Path>>(logfile: P) -> Result<Vec<AmassEntry>> {
    // open the file with BurReader to iter over lines
    let fd = File::open(&logfile)?; 
    let reader = BufReader::new(fd);
    let mut ret: Vec<AmassEntry> = Vec::new();

    // parse json struct
    for line in reader.lines() {
	let line = line?;
	let v: AmassEntry = serde_json::from_str(&line)?; 
	ret.push(v);
    }
    Ok(ret)
}

pub fn is_amass_log<P: AsRef<Path>>(logfile: P) -> bool {
    if let Some(path_str) = logfile.as_ref().to_str() {
	if !path_str.contains("amass") {
	    return false;
	}
	if let Some(ext) = logfile.as_ref().extension() {
	    return match ext.to_str() {
		Some(v) => v == "json",
		None => false,
	    }
	}
    }
    false
}
