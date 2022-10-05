//! Demonstration on how how to use a Linux eBPF module (XDP) for filtering network traffic based on the IP (IPv4, IPv6).
//! This part is the main program that loads the configuration, the eBPF module and communicates the configuration to the eBPF moddule
//! Adaption from: https://github.com/aya-rs/book/blob/main/examples/tc-egress/

use std::net::{self, Ipv4Addr};

use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, HashMap},
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tokio::{signal, task};

use localnet_filter_common::PacketLog;

use localnet_filter_common;

// own modules
pub mod conf;
pub mod network;
pub mod user;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "./conf/localnet-filter.yml")]
    config_path: String, // (2)
}

#[tokio::main]
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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    // load eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../localnet-filter-ebpf/target/bpfel-unknown-none/debug/localnet-filter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../localnet-filter-ebpf/target/bpfel-unknown-none/release/localnet-filter"
    ))?;

    // iterate through configuration and attach to endpoint
    // add/update hashmap for userid for allowed cidr
    for endpoint in config.endpoints {
        for (endpoint_name, endpoint_config) in endpoint {
            info!("Configuring endpoint: {}", endpoint_name);
            // error adding clsact to the interface if it is already added is harmless
            // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.

            for iface in endpoint_config.iface {
                info!("Attaching to interface {} ...", iface);
                let _ = tc::qdisc_add_clsact(&iface);
                let program: &mut SchedClassifier =
                    bpf.program_mut("tc_egress").unwrap().try_into()?;
                program.load()?;
                program.attach(&iface, TcAttachType::Egress)?;
            }
        }
    }

    // (1)
    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST")?)?;

    // (2)
    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).try_into()?;

    // (3)
    blocklist.insert(block_addr, 0, 0)?;


    // Get feedback from eBPF Module about decisions made
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = std::net::Ipv4Addr::from(data.ipv4_address);
                    println!("LOG: SRC {}, ACTION {}, UID {}", src_addr, data.action, data.uid);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
