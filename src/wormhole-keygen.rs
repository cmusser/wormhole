use sodiumoxide::crypto::secretstream::gen_key;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use structopt::StructOpt;

fn main() -> Result<(), Box<dyn Error>> {
    #[derive(Debug, StructOpt)]
    #[structopt(name = "wormhole-keygen", about = "Create secret key for wormhole.")]
    struct Opt {
        /// File containing shared key
        #[structopt(short, long, default_value = "key.yaml")]
        key_file: String,
    }

    let opt = Opt::from_args();

    let key = gen_key();
    let mut file = File::create(&PathBuf::from(&opt.key_file))?;
    let yaml = serde_yaml::to_string(&key)?;
    Ok(file.write_all(yaml.as_bytes())?)
}
