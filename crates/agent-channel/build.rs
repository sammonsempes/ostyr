use std::error::Error;
use std::io::Write;


const PROTO_DIR: &str = "proto";


const PROTO_FILE: &str = "proto/agent_channel.proto";


fn main() -> Result<(), Box<dyn Error>> {
    let descriptors = protox::compile([PROTO_FILE], [PROTO_DIR])?;
    prost_build::Config::new().compile_fds(descriptors)?;
    writeln!(std::io::stdout(), "cargo:rerun-if-changed={PROTO_FILE}")?;
    Ok(())
}
