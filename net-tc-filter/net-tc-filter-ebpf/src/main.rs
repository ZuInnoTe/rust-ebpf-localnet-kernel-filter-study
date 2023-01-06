#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{HashMap, PerfEventArray},
    programs::TcContext,
};
use memoffset::offset_of;

use net_tc_filter_common::Netfilter;
use net_tc_filter_common::PacketLog;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::{ethhdr, iphdr};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1024, 0);

#[map(name = "ENDPOINTLIST")] // contains the local endpoints that we should monitor for connection attempts
                              // key: userid
                              // value: list of tuples (prefix, range)
static mut ENDPOINTLIST: HashMap<u32, Netfilter> =
    HashMap::<u32, Netfilter>::with_max_entries(1024, 0);

#[classifier(name = "tc_egress")]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

///  Decides if a package should be dropped because it is not whitelisted
///
/// # Arguments
/// * `uid` - user id
/// * `address` - IP address to block
///
/// # Returns
/// true if it should be allowed and false if not
///
/// # Examples
/// ```
/// assert_eq!(0u32, super::get_uid_by_name("root").unwrap());
/// ```
fn block_ip(uid: u32, address: u128) -> bool {
    unsafe {
        match ENDPOINTLIST.get(&uid) {
            Some(netfilter) => {
                for (cidr_prefix_num, cidr_range_num) in netfilter.filter {
                    if cidr_prefix_num != 0 {
                        if net_tc_filter_common::range_contains_ip(
                            cidr_prefix_num,
                            cidr_range_num,
                            address,
                        ) {
                            return false;
                        }
                    }
                }
                true
            }
            None => true,
        }
    }
}

/// Classify package via TC
///
/// # Arguments
/// * `ctx` - TC context
///
/// # Returns
/// Action what to do with the package (SHOT or PIPE)
///
fn try_tc_egress(ctx: TcContext) -> Result<i32, i64> {
    // determine protocol
    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    // only process ipv4 and ipv6 packet
    let ip_version: u32 = match h_proto {
        ETH_P_IP => 4,
        ETH_P_IPV6 => 6,
        _ => return Ok(TC_ACT_PIPE),
    };
    // determine destination of the packet
    let destination: u128 = match ip_version {
        4 => u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?) as u128,
        6 => u128::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?),
        _ => 0,
    };
    // determine user id of the socket
    let uid = ctx.get_socket_uid();
    // make a decision what to do with the packet
    let action = if block_ip(uid, destination) {
        TC_ACT_SHOT
    } else {
        TC_ACT_PIPE
    };
    // convert address for making it usable in a PerfEvent
    let mut ip_address: [u32; 4] = [0; 4];
    let mut counter = 0;
    for chunk in (destination as u128).to_le_bytes().chunks(4) {
        ip_address[counter] = u32::from_le_bytes(
            chunk
                .try_into()
                .expect("Internal Error: Size of Chunks is not 4 bytes"),
        );
        counter += 1;
    }
    // create PerfEvent for the user space program to log the decision
    let log_entry = PacketLog {
        ip_address: ip_address,
        ip_version: ip_version,
        action: action,
        uid: uid,
    };
    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }
    // return decision
    Ok(action)
}

// Linux kernel constants
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
