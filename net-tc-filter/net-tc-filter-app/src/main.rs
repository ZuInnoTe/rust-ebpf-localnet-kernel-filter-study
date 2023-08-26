//! Demonstration on how how to use a Linux eBPF module (traffic classifier (tc)) for filtering network traffic based on the IP (IPv4, IPv6).
//! This part is the main program that loads the configuration, the eBPF module and communicates the configuration to the eBPF moddule
//! Adaption from: https://github.com/aya-rs/book/blob/main/examples/tc-egress/



use aya::{
    include_bytes_aligned,
    maps::{HashMap},
    programs::{tc, SchedClassifier, TcAttachType},
    Bpf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info,warn};
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tokio::{signal};

use net_tc_filter_common::Netfilter;

use net_tc_filter_common;

// own modules
pub mod conf;
pub mod network;
pub mod user;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "./conf/net-tc-filter.yml")]
    config_path: String, // (2)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    let config = conf::load_config(opt.config_path).unwrap();
    env_logger::init();
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    // load eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../net-tc-filter-ebpf/target/bpfel-unknown-none/debug/net-tc-filter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../net-tc-filter-ebpf/target/bpfel-unknown-none/release/net-tc-filter"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }


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
            let mut endpointlist: HashMap<_, u32, Netfilter> =
            HashMap::try_from(bpf.map_mut("ENDPOINTLIST").unwrap())?;
    
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
                let mut netfilter = net_tc_filter_common::Netfilter {
                    filter: [(0, 0); net_tc_filter_common::MAX_ENDPOINT_ENTRIES_USER],
                };
                let mut counter: usize = 0;
                for range in &endpoint_config.range {
                    if counter == net_tc_filter_common::MAX_ENDPOINT_ENTRIES_USER {
                        return Err(anyhow::anyhow!(
                            "Too many ip ranges/user. Maximum {}",
                            net_tc_filter_common::MAX_ENDPOINT_ENTRIES_USER
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


    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
