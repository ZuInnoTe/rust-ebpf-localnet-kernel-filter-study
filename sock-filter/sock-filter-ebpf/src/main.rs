#![no_std]
#![no_main]
/// This eBPF program filters all IPv4/IPv6 messages on a socket configured by the user space program.
/// Note: All non-IP protocols are rejected by default
use core::mem;

use aya_bpf::{
    macros::{map, socket_filter},
    maps::HashMap,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;
mod bindings;
use bindings::{ethhdr, iphdr, ipv6hdr};

use memoffset::offset_of;

use sock_filter_common::ConfigEbpf;
use sock_filter_common::Netfilter;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[map(name = "CONFIGLIST")] // contains some configuration items
static mut CONFIGLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[map(name = "ENDPOINTLIST")] // contains the local endpoints that we should monitor for connection attempts
                              // key: userid
                              // value: list of tuples (prefix, range)
static mut ENDPOINTLIST: HashMap<u32, Netfilter> =
    HashMap::<u32, Netfilter>::with_max_entries(1024, 0);

/// This is the "main" function of the eBPF program
#[socket_filter]
pub fn sock_egress(ctx: SkBuffContext) -> i64 {
    match try_sock_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

///  Decides if a package should be forwarded to user space or not
///
/// # Arguments
/// * `uid` - user id
/// * `address` - IP address to block
///
/// # Returns
/// true if it should be forwarded, false if not
///
/// # Examples
/// ```
/// assert_eq!(0u32, super::get_uid_by_name("root").unwrap());
/// ```
fn forward_to_user_space(uid: u32, address: u128) -> bool {
    unsafe {
        match ENDPOINTLIST.get(&uid) {
            Some(netfilter) => {
                for (cidr_prefix_num, cidr_range_num) in netfilter.filter {
                    if cidr_prefix_num != 0 {
                        if sock_filter_common::range_contains_ip(
                            cidr_prefix_num,
                            cidr_range_num,
                            address,
                        ) {
                            return true;
                        }
                    }
                }
                false
            }
            None => false,
        }
    }
}

/// Filter packet via sock
///
/// # Arguments
/// * `ctx` - SkBuffContext
///
/// # Returns
/// 0 to not forwarded the packet to the socket, -1 to forward it to the socket
///
fn try_sock_egress(ctx: SkBuffContext) -> Result<i64, i64> {
    // determine protocol
    let h_proto = unsafe { (*ctx.skb.skb).protocol };

    // only process ipv4 and ipv6 packets
    let ip_version: u32 = match h_proto {
        ETH_P_IP => 4,
        ETH_P_IPV6 => 6,
        _ => return Ok(0), // drop packet
    };
    // determine destination of the packet
    let destination: u128 = match ip_version {
        4 => u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr)).unwrap()) as u128,
        6 => u128::from_be(ctx.load(ETH_HDR_LEN + offset_of!(ipv6hdr, daddr)).unwrap()),
        _ => 0,
    };

    // determine user id of the socket or if all users should have access
    let uid = unsafe {
        match CONFIGLIST.get(&(ConfigEbpf::AllowAll as u32)) {
            Some(_) => 0,
            None => ctx.get_socket_uid(),
        }
    };
    // make a decision what to do with the packet

    let decision = if forward_to_user_space(uid, destination) {
        -1i64
    } else {
        0i64
    };

    match ip_version {
        4 => {
            let ip_address = destination as u32;
            info!(
                &ctx,
                "VERSION {}, DEST {:i}, DECISION {}, UID {}", ip_version, ip_address, decision, uid
            )
        }
        6 => {
            let ip_address = (destination as u128).to_le_bytes();
            info!(
                &ctx,
                "VERSION {}, DEST {:i}, DECISION {}, UID {}", ip_version, ip_address, decision, uid
            )
        }
        _ => info!(&ctx, "Unkown IP version {}, UID {}", ip_version, uid),
    }

    Ok(decision)
}

// Linux kernel constants
const ETH_P_IP: u32 = 0x0008 as u32;
const ETH_P_IPV6: u32 = 0xdd86 as u32;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
