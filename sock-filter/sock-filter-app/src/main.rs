//! Demonstration on how how to use a Linux eBPF module (socket filter) for filtering network traffic based on the IP (IPv4, IPv6).
//! This part is the main program that loads the configuration, the eBPF module and communicates the configuration to the eBPF moddule
//! Adaption from: https://github.com/aya-rs/book/blob/main/examples/tc-egress/

use aya::{include_bytes_aligned, maps::HashMap, programs::SocketFilter, Ebpf};
use clap::Parser;
use log::{error, info};
use sock_filter_common;
use sock_filter_common::ConfigEbpf;
use sock_filter_common::Netfilter;
use tokio::signal;
use tokio::sync::broadcast;

// own modules
pub mod conf;
pub mod network;
pub mod user;

// command line options
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "./conf/sock-filter.yml")]
    config_path: String, // path to config file
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    let config = conf::load_config(opt.config_path).unwrap();
    env_logger::init();
    // communicate to async processes events, e.g. terminate application
    let (tx_sign, mut _rx_sign) = broadcast::channel::<u32>(2);
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    // load eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../sockfilter-ebpf/target/bpfel-unknown-none/debug/sock-filter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../sock-filter-ebpf/target/bpfel-unknown-none/release/sock-filter"
    ))?;
    // iterate through configuration and attach to endpoint
    // add/update hashmap for userid for allowed cidr
    for endpoint in config.endpoints {
        for (endpoint_name, endpoint_config) in endpoint {
            let mut endpointlist: HashMap<_, u32, Netfilter> =
                HashMap::try_from(bpf.map_mut("ENDPOINTLIST").unwrap())?;

            let mut allow_all_users = false;
            // add user
            for username in &endpoint_config.filter {
                let uid = match username.as_str() {
                    "*" => {
                        info!("Allowing filtering of socket traffic of all users");
                        allow_all_users = true;
                        0
                    }
                    _ => match user::get_uid_by_name(&username) {
                        Ok(uid) => {
                            info!("Adding rules for user {} with id {}", username, uid);
                            uid
                        }
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
                    },
                };

                // add range
                let mut netfilter = sock_filter_common::Netfilter {
                    filter: [(0, 0); sock_filter_common::MAX_ENDPOINT_ENTRIES_USER],
                };
                let mut counter: usize = 0;
                for range in &endpoint_config.range {
                    if counter == sock_filter_common::MAX_ENDPOINT_ENTRIES_USER {
                        return Err(anyhow::anyhow!(
                            "Too many ip ranges/user. Maximum {}",
                            sock_filter_common::MAX_ENDPOINT_ENTRIES_USER
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
            if allow_all_users == true {
                let mut configlist: HashMap<_, u32, u32> =
                    HashMap::try_from(bpf.map_mut("CONFIGLIST").unwrap())?;
                configlist.insert(ConfigEbpf::AllowAll as u32, 1, 0)?;
            }
            info!("Configuring endpoint: {}", endpoint_name);
            // attach eBPF program to specific network interface
            for iface in endpoint_config.iface {
                info!("Attaching to interface {} ...", iface);
                let raw_sock = attach_interface_raw_socket(&iface).unwrap();
                let program: &mut SocketFilter =
                    bpf.program_mut("sock_egress").unwrap().try_into()?;

                program.load()?;

                // spawn socket reading processes - read all packets received on the raw socket
                let read_raw_sock = raw_sock.clone();

                program.attach(read_raw_sock.clone())?;
                info!("Attaching complete ...");
                info!("Socket  reading process start.");
                let sock = raw_sock.clone();
                let sock_subscriber = tx_sign.subscribe(); // this is used as a notification channel for the read socket thread to be notified when the application exits
                tokio::spawn(async move { read_socket(sock, sock_subscriber).await });
            }
        }
    }

    // waiting for end
    info!("Waiting for Ctrl-C...");

    signal::ctrl_c().await?;

    info!("Exiting...");
    tx_sign.send(1).unwrap();
    Ok(())
}

/// reads a message from a raw socket and displays some basic packet information of received packets, such as IP version, IP addresses etc.
///
/// # Arguments
/// * `sock` - raw socket from which to read messages
/// * `terminate_receiver` - a Tokia broadcast receiver that is reguarly checked if the application terminates and thus the read process should also terminate
///
async fn read_socket(
    mut sock: network::SimpleRawSocket,
    terminate_receiver: tokio::sync::broadcast::Receiver<u32>,
) {
    while terminate_receiver.is_empty() {
        // thread has not be asked to shut down
        let mut buffer: [u8; 65536] = [0; 65536];
        match sock.read(&mut buffer) {
            // read from the raw socket
            Ok(res) => {
                if res > 0 {
                    let mut info_str: String = "".to_string();
                    info_str.push_str("User space: raw socket received packet \n");
                    let mut data: Vec<u8> = Vec::new();
                    data.extend_from_slice(&buffer[0..(res as usize) - 1]);
                    let raw_data_parsed = network::SimpleRawSocketData::parse(data).unwrap();
                    info_str.push_str(
                        format!("IP Version:  {:?}\n", raw_data_parsed.metadata.ip_version)
                            .as_str(),
                    );
                    info_str.push_str(
                        format!("Transport:  {:?}\n", raw_data_parsed.metadata.transport).as_str(),
                    );
                    info_str.push_str(
                        format!("Source IP:  {:?}\n", raw_data_parsed.metadata.src_ip_addr)
                            .as_str(),
                    );
                    info_str.push_str(
                        format!(
                            "Destination IP:  {:?}",
                            raw_data_parsed.metadata.dst_ip_addr
                        )
                        .as_str(),
                    );
                    info!("{}", info_str);
                }
            }
            Err(message) => {
                error!("{}", message);
                continue;
            }
        };
    }
    info!("Shutting down");
    match sock.close() {
        Ok(()) => (),
        Err(err) => error! {"Error closing socket. Message: {}", err},
    };
}

/// Attaches raw sockets for IPv4 and IPv6 to a given interface
///
/// # Arguments
/// * `iface` - A str with the interface name, e.g. "eth0"
///
/// # Returns
/// A tuple with the RawFd for IPv4 and IPv6
///
/// ```
fn attach_interface_raw_socket(iface: &str) -> Result<network::SimpleRawSocket, String> {
    Ok(network::SimpleRawSocket::new(iface).unwrap())
}
