#![no_std]


#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: i32,
    pub uid: u32
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}


pub const MAX_ENDPOINT_ENTRIES_USER: usize =10; // should be always a multiplicator of two as we need to configure a prefix and a range

/// Minimal function to determine if an ip is contained in a given range (or CIDR). This works for IPv4 and IPv6. 
/// We work here with primitive types only and do not provide conversion of an IP (range) string to u128 as this function must be also usable in a eBPF module
///
/// # Arguments
/// * `range_mask` - mask of the range that determines the size of the range
/// * `prefix` - prefix of the range
/// * `ip` - IP to check if is in the given IP address range
/// 
/// Returns true if IP is contained in range, false if not
pub fn range_contains_ip(range_mask: u128, prefix: u128, ip: u128) -> bool {
    ip & range_mask == prefix
}



#[cfg(test)]
mod tests {


    #[test]
    fn test_cidrv4_ipv4_local() {
        let range_mask: u128 = 0xff000000; // /8
        let prefix: u128 = 2130706432; // 127.0.0.0 (prefix)
        // inside
        let ip_in: u128 = 2130706433; // 127.0.0.1 (loopback)
        assert!(super::range_contains_ip(range_mask, prefix, ip_in));
        // outside
        let ip_out: u128 = 3232281089; // 192.168.178.1
        assert_eq!(false, super::range_contains_ip(range_mask, prefix, ip_out));
    }

    #[test]
    fn test_cidrv6_ipv6_local() {
        let range_mask: u128 = 0xffffffffffffffffffffffffffffffff; // /128
        let prefix: u128 = 1;
        // inside
        let ip_in: u128 = 1; // ::1 (loopback)
        assert!(super::range_contains_ip(range_mask, prefix, ip_in));
        // outside
        let ip_out: u128 = 1329227995784915872903807060280344577; // 100:0:0:0:0:0:0:1
        assert_eq!(false, super::range_contains_ip(range_mask, prefix, ip_out));
    }

}