//! Demonstration on how how to use a Linux eBPF module (uprobe) for retrieving plain text messages from unencrypted text passed to the OpenSSL library
//! This part is the main program that loads the configuration, the eBPF module and communicates the configuration to the eBPF moddule

use aya::{
    Ebpf, include_bytes_aligned, maps::RingBuf, programs::UProbe, programs::uprobe::UProbeScope,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::convert::TryFrom;
use tokio::signal;

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
    match EbpfLogger::init(&mut bpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
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
                application_definition.openssl_lib.as_str(),
                UProbeScope::AllProcesses,
            )?;

            let program_ossreadprobe_ret: &mut UProbe =
                bpf.program_mut("osslreadretprobe").unwrap().try_into()?;
            program_ossreadprobe_ret.load()?;
            program_ossreadprobe_ret.attach(
                "SSL_read",
                &application_definition.openssl_lib,
                UProbeScope::AllProcesses,
            )?;
            // attach probes for write
            let program_osswriteprobe: &mut UProbe =
                bpf.program_mut("osslwriteprobe").unwrap().try_into()?;
            program_osswriteprobe.load()?;
            program_osswriteprobe.attach(
                "SSL_write",
                &application_definition.openssl_lib,
                UProbeScope::AllProcesses,
            )?;
            let program_osswriteprobe_ret: &mut UProbe =
                bpf.program_mut("osslwriteretprobe").unwrap().try_into()?;
            program_osswriteprobe_ret.load()?;
            program_osswriteprobe_ret.attach(
                "SSL_write",
                &application_definition.openssl_lib,
                UProbeScope::AllProcesses,
            )?;
        }
    }

    // Get feedback from eBPF module of calls to SSL_read with unecrypted data
    let ssl_read_ringbuf = RingBuf::try_from(bpf.take_map("SSLREADDATABUF").unwrap())?;
    let mut poll =
        tokio::io::unix::AsyncFd::with_interest(ssl_read_ringbuf, tokio::io::Interest::READABLE)?;
    tokio::task::spawn(async move {
        loop {
            let mut guard = poll.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                // get the size of the data to read
                let data_len = u32::from_le_bytes(
                    <[u8; 4]>::try_from(item.chunks(4).next().unwrap()).unwrap(),
                );
                let all_data_vec = item.to_vec();
                let all_data = all_data_vec.as_slice();
                let size_of_length = size_of::<u32>() as u32;
                // extract the content
                let content =
                    &all_data[size_of_length as usize..(data_len + size_of_length) as usize];
                match std::str::from_utf8(content) {
                    Ok(utf8_str) => info!("Unencrypted SSL_read data: {}", utf8_str),
                    Err(err) => warn!("Data is not valid UTF8 data: {}", err),
                };
            }
            guard.clear_ready();
        }
    });

    // Get feedback from eBPF module of calls to SSL_write with unecrypted data
    let ssl_write_ringbuf = RingBuf::try_from(bpf.take_map("SSLWRITEDATABUF").unwrap())?;
    let mut poll =
        tokio::io::unix::AsyncFd::with_interest(ssl_write_ringbuf, tokio::io::Interest::READABLE)?;
    tokio::task::spawn(async move {
        loop {
            let mut guard = poll.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                // get the size of the data to read
                let data_len = u32::from_le_bytes(
                    <[u8; 4]>::try_from(item.chunks(4).next().unwrap()).unwrap(),
                );
                let all_data_vec = item.to_vec();
                let all_data = all_data_vec.as_slice();
                let size_of_length = size_of::<u32>() as u32;
                // extract the content
                let content =
                    &all_data[size_of_length as usize..(data_len + size_of_length) as usize];
                match std::str::from_utf8(content) {
                    Ok(utf8_str) => info!("Unencrypted SSL_write data: {}", utf8_str),
                    Err(err) => warn!("Data is not valid UTF8 data: {}", err),
                };
            }
            guard.clear_ready();
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
