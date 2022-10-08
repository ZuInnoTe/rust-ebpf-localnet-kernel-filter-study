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

use localnet_filter_common::Netfilter;
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

    let mut endpointlist: HashMap<_, u32, Netfilter> =
        HashMap::try_from(bpf.map_mut("ENDPOINTLIST")?)?;

    // iterate through configuration and attach to endpoint
    // add/update hashmap for userid for allowed cidr
    for endpoint in config.endpoints {
        for (endpoint_name, endpoint_config) in endpoint {
            info!("Configuring endpoint: {}", endpoint_name);

            for iface in endpoint_config.iface {
                info!("Attaching to interface {} ...", iface);
                let _ = tc::qdisc_add_clsact(&iface);
                let program: &mut SchedClassifier =
                    bpf.program_mut("tc_egress").unwrap().try_into()?;
                program.load()?;
                program.attach(&iface, TcAttachType::Egress)?;
            }
            // add user
            for user in &endpoint_config.allow {
                let uid = match user::get_uid_by_name(&user) {
                    Ok(uid) => uid,
                    Err(err) => {
                        let error_msg = match err {
                            user::UserInformationError::InvalidUserName => "Invalid user name",
                            user::UserInformationError::NoUserInformationAvailable => {
                                "Unknown user name"
                            }
                            _ => "Internal Error",
                        };

                        return Err(anyhow::anyhow!("{}", error_msg));
                    }
                };
                info!("Adding rules for user {} with id {}", user, uid);
                // add range
                let mut netfilter = localnet_filter_common::Netfilter {
                    filter: [(0, 0); localnet_filter_common::MAX_ENDPOINT_ENTRIES_USER],
                };
                let mut counter: usize = 0;
                for range in &endpoint_config.range {
                    if counter == localnet_filter_common::MAX_ENDPOINT_ENTRIES_USER {
                        return Err(anyhow::anyhow!(
                            "Too many ip ranges/user. Maximum {}",
                            localnet_filter_common::MAX_ENDPOINT_ENTRIES_USER
                        ));
                    }
                    let (cidr_prefix, cidr_range) = match network::split_cidr(range) {
                        Ok(result) => result,
                        Err(error_msg) => return Err(anyhow::anyhow!("{}", error_msg)),
                    };
                    info!("Adding prefix {} range {}", cidr_prefix, cidr_range);
                    let cidr_prefix_num =
                        match network::convert_ip_addr_str_to_unsigned_integer(&cidr_prefix) {
                            Ok(num) => num,
                            Err(error_msg) => return Err(anyhow::anyhow!("{}", error_msg)),
                        };
                    let cidr_range_num = match network::convert_range_str_to_bit_mask(&cidr_range) {
                        Ok(num) => num,
                        Err(error_msg) => return Err(anyhow::anyhow!("{}", error_msg)),
                    };
                    netfilter.filter[counter] = (cidr_prefix_num, cidr_range_num);
                    counter += 1;
                }
                endpointlist.insert(uid, netfilter, 0)?;
            }
        }
    }

    /*      // (1)
       let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST")?)?;

    // (2)
    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).try_into()?;

    // (3)
    blocklist.insert(block_addr, 0, 0)?;*/

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
                    let mut ip_addr_bytes: [u8; 16] = [0; 16];
                    let mut counter = 0;
                    for chunk in data.ip_address {
                        let chunk_le_bytes = chunk.to_le_bytes();
                        for byte in chunk_le_bytes {
                            ip_addr_bytes[counter] = byte;
                            counter += 1;
                        }
                    }
                    let ip_addr = u128::from_le_bytes(ip_addr_bytes);
                    let src_addr: Option<std::net::IpAddr> = match data.ip_version {
                        4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                            ip_addr as u32,
                        ))),
                        6 => Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_addr))),
                        _ => None,
                    };
                    match src_addr {
                        Some(src_addr) => println!(
                            "LOG: SRC {}, ACTION {}, UID {}",
                            src_addr, data.action, data.uid
                        ),
                        None => println!(
                            "Error unknown IP version {} for uid {}",
                            data.ip_version, data.uid
                        ),
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
