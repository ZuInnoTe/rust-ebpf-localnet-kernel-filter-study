/// Adaption from: https://github.com/aya-rs/book/tree/main/examples/myapp-01
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tokio::signal; // (1)




// own modules
pub mod conf;
pub mod net;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "./conf/localnet-filter.yml")]
    config_path: String, // (2)
}

#[tokio::main] // (3)
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let config = conf::load_config(opt.config_path).unwrap();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // load eBF program
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../localnet-filter-ebpf/target/bpfel-unknown-none/debug/localnet-filter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../localnet-filter-ebpf/target/bpfel-unknown-none/release/localnet-filter"
    ))?;
    // init logger
    BpfLogger::init(&mut bpf)?;
    // load eBPF program in the kernel
    let program: &mut Xdp = bpf.program_mut("localnetfilter").unwrap().try_into()?;
    program.load()?;
    // convert each ip/cidr to bit representation
    // convert username to uid
    // communicate user ids and ips and send to ebpf program
    // iterate through configuration and attach to endpoint
    for endpoint in config.endpoints {
        for (endpoint_name, endpoint_config) in endpoint {
            for iface in endpoint_config.iface {
                info!("Attaching to interface {} ...", iface);
                program.attach(iface.as_str(), XdpFlags::default())
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
            }
        }
    }
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}



