//! Demonstration on how how to use a Linux eBPF module (traffic classifier (tc)) for filtering network traffic based on the IP (IPv4, IPv6).
//! This part is the main program that loads the configuration, the eBPF module and communicates the configuration to the eBPF moddule
//! Adaption from: https://github.com/aya-rs/book/blob/main/examples/tc-egress/

use aya::{
    include_bytes_aligned, maps::perf::AsyncPerfEventArray, programs::UProbe, util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, task};

// own modules
pub mod conf;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "./conf/uprobe-libcall-filter.yml")]
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
        "../../uprobe-libcall-filter-ebpf/target/bpfel-unknown-none/debug/uprobe-libcall-filter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../uprobe-libcall-filter-ebpf/target/bpfel-unknown-none/release/uprobe-libcall-filter"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // iterate through configuration and attach uprobe to each application
    for (operation, operation_definition) in config.applications {
        info! {"Configuring operation {}",operation};
        for (application, application_definition) in operation_definition {
            info!("Configuring application: {}", application);
            info!(
                "Configuring openssl_lib: {}",
                application_definition.openssl_lib
            );

            // attach probes for read
            let program_ossreadprobe: &mut UProbe =
                bpf.program_mut("osslreadprobe").unwrap().try_into()?;
            program_ossreadprobe.load()?;
            program_ossreadprobe.attach(
                "SSL_read",
                &application_definition.openssl_lib,
                None,
                None,
            )?;

            let program_ossreadprobe_ret: &mut UProbe =
                bpf.program_mut("osslreadretprobe").unwrap().try_into()?;
            program_ossreadprobe_ret.load()?;
            program_ossreadprobe_ret.attach(
                "SSL_read",
                &application_definition.openssl_lib,
                None,
                None,
            )?;
            // attach probes for write
            let program_osswriteprobe: &mut UProbe =
                bpf.program_mut("osslwriteprobe").unwrap().try_into()?;
            program_osswriteprobe.load()?;
            program_osswriteprobe.attach(
                "SSL_write",
                &application_definition.openssl_lib,
                None,
                None,
            )?;
            let program_osswriteprobe_ret: &mut UProbe =
                bpf.program_mut("osslwriteretprobe").unwrap().try_into()?;
            program_osswriteprobe_ret.load()?;
            program_osswriteprobe_ret.attach(
                "SSL_write",
                &application_definition.openssl_lib,
                None,
                None,
            )?;
        }
    }

    // Get feedback from eBPF module of calls to SSL_read with unecrypted data
    let mut ssl_read_perf_array =
        AsyncPerfEventArray::try_from(bpf.take_map("SSLREADDATA").unwrap())?;

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let mut buf = ssl_read_perf_array.open(cpu_id, None)?;
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(uprobe_libcall_filter_common::DATA_BUF_CAPACITY))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                #[allow(clippy::needless_range_loop)]
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    info!("Unencrypted SSL_read data: {}", unsafe {
                        std::str::from_utf8_unchecked(buf)
                    })
                }
            }
        });
    }

    // Get feedback from eBPF module of calls to SSL_write with unecrypted data
    let mut ssl_write_perf_array =
        AsyncPerfEventArray::try_from(bpf.take_map("SSLWRITEDATA").unwrap())?;

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let mut buf = ssl_write_perf_array.open(cpu_id, None)?;
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(uprobe_libcall_filter_common::DATA_BUF_CAPACITY))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                #[allow(clippy::needless_range_loop)]
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    info!("Unencrypted SSL_write data: {}", unsafe {
                        std::str::from_utf8_unchecked(buf)
                    })
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
