#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;


#[map(name = "LOCALENDPOINTLIST")] // contains the local endpoints that we should monitor for connection attempts
static mut LOCALENDPOINTLIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);

#[map(name = "UIDLIST")] // contains the uid we should monitor for
static mut UIDLIST: HashMap<u32, u32> =
        HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp(name="localnetfilter")] 
pub fn localnet_filter(ctx: XdpContext) -> u32 {
    
    match unsafe { try_localnet_filter(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn filter_ip(address: u32) -> bool {
    unsafe { LOCALENDPOINTLIST.get(&address).is_some() }
}

unsafe fn try_localnet_filter(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    // check if uid matches
        // if yes check if IP address is on list
            // if yes forward to user space program
    // if no - let it pass
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}