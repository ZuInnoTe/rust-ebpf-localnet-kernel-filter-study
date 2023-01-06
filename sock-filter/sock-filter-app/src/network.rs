//! Module for handling networking relevant to filtering, such as determining if a IP address falls within a networking range

use std::io;
use std::net::IpAddr;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, RawFd};

use log::{error, info};

const MAX_BIT_MASK_SIZE: u32 = 128; // IPv6 128 Bit

// Kernel data structure: EthHdr
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SimpleEthHdr {
    pub h_dest: [u8; 6usize],
    pub h_source: [u8; 6usize],
    pub h_proto: u16,
}

// Kernel data structure: IpHdr (v4)
/// IP Header https://www.rfc-editor.org/rfc/rfc791
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SimpleIpHdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

// Kernel data structure: Ipv6Hdr (v6)
/// IPv6 Header https://www.rfc-editor.org/rfc/rfc2460
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SimpleIpv6Hdr {
    pub version_tc: u8,
    pub tc_flow_lbl: [u8; 3usize],
    pub payload_len: u16,
    pub nexthdr: u8,
    pub hop_limit: u8,
    pub saddr: [u32; 4usize],
    pub daddr: [u32; 4usize],
}

/// Generic IP Header that represent an IP header in different IP versions
pub enum IpHdr {
    IpV4(SimpleIpHdr),
    IpV6(SimpleIpv6Hdr),
}

/// SimpleRawSocketMetadata - some metadata associated with a packet received through a raw socket
#[derive(Debug)]
pub struct SimpleRawSocketMetadata {
    pub ip_version: IpVersion,
    pub transport: TransportType,
    pub src_ip_addr: IpAddr,
    pub dst_ip_addr: IpAddr,
}

/// SimpleRawSocketData - A simple representation of a packet received through a raw socket - its data and metadata
#[derive(Debug)]
pub struct SimpleRawSocketData {
    pub metadata: SimpleRawSocketMetadata,
    pub data: Vec<u8>,
}

/// IP Version of a packet
#[derive(Debug, Copy, Clone)]
pub enum IpVersion {
    IpV4,
    IpV6,
    Unknown,
}

/// Transort type of a packet
#[derive(Debug)]
pub enum TransportType {
    Tcp,
    Udp,
    Unknown,
}

impl SimpleRawSocketData {
    /// Parses a raw packet from a raw socket that includes - at least - an ethernet header and an ip header
    ///
    /// # Arguments
    /// * `data` - A vector containing the bytes of a raw packet
    ///
    /// # Returns
    ///  Returns the metadata and data of the packet or an error string if the packet cannot be parsed properly or if it is not an IP packet
    ///
    pub fn parse(mut data: Vec<u8>) -> Result<SimpleRawSocketData, String> {
        let simple_eth_hdr: SimpleEthHdr = Self::parse_eth_hdr(&mut data)?;
        // read IP version
        let ip_version = match simple_eth_hdr.h_proto {
            0x0800 => IpVersion::IpV4, // Ipv4
            0x86dd => IpVersion::IpV6, // Ipv6
            _ => return Err("Unknown Network Protocol".to_string()),
        };
        // parse IP header
        let iphdr = match ip_version {
            IpVersion::IpV4 => IpHdr::IpV4(Self::parse_ipv4_hdr(&mut data)?),
            IpVersion::IpV6 => IpHdr::IpV6(Self::parse_ipv6_hdr(&mut data)?),
            _ => return Err("Unknown Network Protocol".to_string()),
        };
        // get transport protocol, cf. https://www.rfc-editor.org/rfc/rfc790
        let transport = match iphdr {
            IpHdr::IpV4(hdr) => match hdr.protocol {
                6 => TransportType::Tcp,
                17 => TransportType::Udp,
                _ => TransportType::Unknown,
            },
            IpHdr::IpV6(hdr) => match hdr.nexthdr {
                6 => TransportType::Tcp,
                17 => TransportType::Udp,
                _ => TransportType::Unknown,
            },
        };
        // determine IP src addr
        let src_ip_addr: IpAddr = match iphdr {
            IpHdr::IpV4(hdr) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(hdr.saddr)),
            IpHdr::IpV6(hdr) => {
                let mut ip_addr_bytes: [u8; 16] = [0; 16];
                let mut counter = 0;
                for chunk in hdr.saddr {
                    let chunk_le_bytes = chunk.to_be_bytes();
                    for byte in chunk_le_bytes {
                        ip_addr_bytes[counter] = byte;
                        counter += 1;
                    }
                }
                let ip_addr = u128::from_be_bytes(ip_addr_bytes);
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_addr))
            }
        };
        // determine IP dst addr
        let dst_ip_addr: IpAddr = match iphdr {
            IpHdr::IpV4(hdr) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(hdr.daddr)),
            IpHdr::IpV6(hdr) => {
                let mut ip_addr_bytes: [u8; 16] = [0; 16];
                let mut counter = 0;
                for chunk in hdr.daddr {
                    let chunk_le_bytes = chunk.to_be_bytes();
                    for byte in chunk_le_bytes {
                        ip_addr_bytes[counter] = byte;
                        counter += 1;
                    }
                }
                let ip_addr = u128::from_be_bytes(ip_addr_bytes);
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_addr))
            }
        };
        let metadata = SimpleRawSocketMetadata {
            ip_version: ip_version,
            transport: transport,
            src_ip_addr: src_ip_addr,
            dst_ip_addr: dst_ip_addr,
        };
        Ok(SimpleRawSocketData {
            metadata: metadata,
            data: data,
        })
    }

    /// Parses the ethernet header from a raw packet
    ///
    /// # Arguments
    /// * `data` - A vector containing the bytes of a raw packet. Note: The Ethernet header is removed from the data during parsing
    ///
    /// # Returns
    ///  Returns the parsed ethernet header or an error string if the packet cannot be parsed properly
    ///
    fn parse_eth_hdr(data: &mut Vec<u8>) -> Result<SimpleEthHdr, String> {
        Ok(SimpleEthHdr {
            h_dest: {
                let data_array: [u8; 6] = data
                    .drain(..6)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing Ethernet header");
                data_array
            },
            h_source: {
                let data_array: [u8; 6] = data
                    .drain(..6)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing Ethernet header");
                data_array
            },
            h_proto: {
                let data_array: [u8; 2] = data
                    .drain(..2)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing Ethernet header");
                u16::from_be_bytes(data_array)
            },
        })
    }

    /// Parses the ipv4 header from a raw packet
    ///
    /// # Arguments
    /// * `data` - A vector containing the bytes of a raw packet. Note: the bytes containing the IPv4 header are removed from it
    ///
    /// # Returns
    ///  Returns the parsed IPv4 header or an error string if the packet cannot be parsed properly
    ///
    fn parse_ipv4_hdr(data: &mut Vec<u8>) -> Result<SimpleIpHdr, String> {
        Ok(SimpleIpHdr {
            version_ihl: {
                let data_array: [u8; 1] = data
                    .drain(..1)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                data_array[0]
            },
            tos: {
                let data_array: [u8; 1] = data
                    .drain(..1)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                data_array[0]
            },
            tot_len: {
                let data_array: [u8; 2] = data
                    .drain(..2)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                u16::from_be_bytes(data_array)
            },
            id: {
                let data_array: [u8; 2] = data
                    .drain(..2)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                u16::from_be_bytes(data_array)
            },
            frag_off: {
                let data_array: [u8; 2] = data
                    .drain(..2)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                u16::from_be_bytes(data_array)
            },
            ttl: {
                let data_array: [u8; 1] = data
                    .drain(..1)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                data_array[0]
            },
            protocol: {
                let data_array: [u8; 1] = data
                    .drain(..1)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                data_array[0]
            },
            check: {
                let data_array: [u8; 2] = data
                    .drain(..2)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                u16::from_be_bytes(data_array)
            },
            saddr: {
                let data_array: [u8; 4] = data
                    .drain(..4)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                u32::from_be_bytes(data_array)
            },
            daddr: {
                let data_array: [u8; 4] = data
                    .drain(..4)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                u32::from_be_bytes(data_array)
            },
        })
    }

    /// Parses the ipv6 header from a raw packet
    ///
    /// # Arguments
    /// * `data` - A vector containing the bytes of a raw packet. Note: the bytes containing the IPv6 header are removed from it
    ///
    /// # Returns
    ///  Returns the parsed IPv6 header or an error string if the packet cannot be parsed properly
    ///
    fn parse_ipv6_hdr(data: &mut Vec<u8>) -> Result<SimpleIpv6Hdr, String> {
        Ok(SimpleIpv6Hdr {
            version_tc: {
                let data_array: [u8; 1] = data
                    .drain(..1)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                data_array[0]
            },
            tc_flow_lbl: {
                let data_array: [u8; 3] = data
                    .drain(..3)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                data_array
            },
            payload_len: {
                let data_array: [u8; 2] = data
                    .drain(..2)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                u16::from_be_bytes(data_array)
            },
            nexthdr: {
                let data_array: [u8; 1] = data
                    .drain(..1)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                data_array[0]
            },
            hop_limit: {
                let data_array: [u8; 1] = data
                    .drain(..1)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                data_array[0]
            },
            saddr: {
                let data_array: [u8; 16] = data
                    .drain(..16)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                let mut saddr_array: [u32; 4] = [0; 4];
                for n in 0..4 {
                    saddr_array[n] = u32::from_be_bytes(
                        data_array[n * 4..(n + 1) * 4]
                            .try_into()
                            .expect("Invalid length of array"),
                    );
                }
                saddr_array
            },
            daddr: {
                let data_array: [u8; 16] = data
                    .drain(..16)
                    .as_slice()
                    .try_into()
                    .expect("Cannot fetch enough data for parsing IP header");
                let mut daddr_array: [u32; 4] = [0; 4];
                for n in 0..4 {
                    daddr_array[n] = u32::from_be_bytes(
                        data_array[n * 4..(n + 1) * 4]
                            .try_into()
                            .expect("Invalid length of array"),
                    );
                }
                daddr_array
            },
        })
    }
}

/// SimpleRawSocket is a raw socket (https://linux.die.net/man/7/raw) to attach the eBPF to all network traffic
#[derive(Debug, Clone)]
pub struct SimpleRawSocket {
    fd: RawFd,
}

impl SimpleRawSocket {
    /// Creates a new raw socket and binds it to the specific device
    ///
    /// # Arguments
    /// * `iface` to which interface the raw socket should be bound
    ///
    /// # Returns
    /// A raw socket or in case of an error a error message
    ///
    pub fn new(iface: &str) -> Result<SimpleRawSocket, String> {
        // create raw socket
        let fd: i32 = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };

        if fd < 0 {
            return Err("Cannot create raw socket".to_string());
        }

        // set non-blocking
        let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if fd_flags < 0 {
            return Err("Cannot get raw socket flags".to_string());
        }
        let non_blocking_fd =
            unsafe { libc::fcntl(fd, libc::F_SETFL, fd_flags | libc::O_NONBLOCK) };
        if non_blocking_fd < 0 {
            return Err("Cannot set raw socket to non-blocking".to_string());
        }
        // attach to device
        // bind sockets to interface
        let iface_str = unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(iface.as_bytes()) };
        let sock_int_struct = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: unsafe { libc::if_nametoindex(iface_str.as_ptr() as *const libc::c_char) }
                .try_into()
                .unwrap(),
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        // Some OS require an explicit binding
        let bind_res = unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(sock_int_struct) as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if bind_res < 0 {
            info!("bind: {} ", io::Error::last_os_error());
            return Err("Cannot bind to network interface".to_string());
        };
        // Linux requires socket option for binding
        let setsock_opt = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface_str.as_ptr() as *const libc::c_void,
                iface.len() as u32,
            )
        };
        if setsock_opt < 0 {
            error!("{}", io::Error::last_os_error());
            return Err("Cannot set raw socket option".to_string());
        };
        Ok(SimpleRawSocket { fd: fd })
    }

    /// Read from a raw socket
    ///
    /// # Arguments
    /// * `buffer` : a buffer in which to put the data read from the socket
    ///
    /// # Returns
    /// The number of bytes read from the socket and put in the buffer or an error message in case of an error. Note: if no data is currently available then it will immediately return 0 bytes. There is no blocking read.
    pub fn read(&mut self, buffer: &mut [u8]) -> Result<isize, String> {
        // we check first if something is ready to be fetched
        let mut pollfd = [libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN | libc::POLLPRI,
            revents: 0,
        }; 1];

        let timeout = 1000; // 1 second

        let pollresult = unsafe { libc::poll(&mut pollfd as *mut libc::pollfd, 1, timeout) };
        // something is ready to be fetched
        if pollresult > 0 && pollfd[0].revents == libc::POLLIN {
            match unsafe {
                libc::recv(
                    self.as_raw_fd(),
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                )
            } {
                res if res >= 0 => Ok(res),
                _ => Err(format!("Error: {}", io::Error::last_os_error()).to_string()),
            }
        }
        // nothing can be read return 0
        else {
            Ok(0)
        }
    }

    /// Close the raw socket
    ///
    /// # Returns
    /// () in case the socket was closed or an io::Error::last_os_error in case of an error
    ///
    pub fn close(&mut self) -> io::Result<()> {
        let shutdown_socket = unsafe { libc::shutdown(self.fd, 2) };
        let closed_socket = unsafe { libc::close(self.fd) };
        match shutdown_socket {
            -1 => return Err(io::Error::last_os_error()),
            _ => (),
        };
        match closed_socket {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}

/// Get the fd of the socket
impl AsFd for SimpleRawSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // Safety: `OwnedFd` and `BorrowedFd` have the same validity
        // invariants, and the `BorrowdFd` is bounded by the lifetime
        // of `&self`.
        unsafe { BorrowedFd::borrow_raw(self.fd.as_raw_fd()) }
    }
}

/// Get the raw fd of the socket
impl AsRawFd for SimpleRawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Splits a CIDR into the prefix (ip address) and range
///
/// # Arguments
/// * `cidr` - A string representing a cidr, e.g. "127.0.0.1/8", "::1/128"
///
/// # Returns
/// A tuple with the prefix and the range, or an error in case it is not valid
///
/// # Examples
/// ```
/// assert_eq!(("127.0.0.1","8"),   csplit_cidr("127.0.0.1/8").unwrap());
/// ```
pub fn split_cidr(cidr: &String) -> Result<(String, String), String> {
    let v: Vec<&str> = cidr.split('/').collect();
    // test if a valid cidr is provided
    if v.len() != 2 {
        return Err("Invalid Cidr".to_string());
    }
    // test if range is numeric
    match v[1].to_string().parse::<u32>() {
        Ok(num) => {
            if num > MAX_BIT_MASK_SIZE {
                return Err(format!("Invalid range: {}", num));
            }
        }
        Err(_) => return Err("Cidr is not numeric".to_string()),
    }
    Ok((v[0].to_string(), v[1].to_string()))
}

/// Converts an IP address to a integer representation
///
/// # Arguments
/// * `ip_addr` - A string representing an IP address, e.g. "127.0.0.1", "::1"
///
/// # Returns
/// The integer representation of the IP address or an error in case it is not valid
///
/// # Examples
/// ```
/// assert_eq!(2130706433,   convert_ip_addr_str_to_unsigned_integer("127.0.0.1").unwrap());
/// ```
pub fn convert_ip_addr_str_to_unsigned_integer(
    ip_addr: &str,
) -> Result<u128, std::net::AddrParseError> {
    let ip_addr: IpAddr = ip_addr.parse()?;
    let ip_int_representation: u128 = match ip_addr {
        IpAddr::V4(ip4) => u32::from(ip4) as u128,
        IpAddr::V6(ip6) => u128::from(ip6),
    };
    Ok(ip_int_representation)
}

/// Converts a range into its corresponding bit representation
///
/// # Arguments
/// * `range` - The range as str, e.g. "8"
///
/// # Returns
/// The bit mask as u128 or in case of an error a string with the error message
///
/// # Examples
/// ```
///         assert_eq!(0b11111111u128,super::convert_range_str_to_bit_mask("8").unwrap());
/// ```
pub fn convert_range_str_to_bit_mask(range: &str) -> Result<u128, String> {
    let range_num = match range.parse::<u32>() {
        Ok(num) => {
            if num > MAX_BIT_MASK_SIZE {
                return Err(format!("Invalid range: {}", num));
            }
            num
        }
        Err(_) => return Err("Cidr is not numeric".to_string()),
    };
    let mask: u128 = u128::MAX >> (MAX_BIT_MASK_SIZE - range_num);
    Ok(mask)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_split_cidr_valid() {
        assert_eq!(
            ("127.0.0.1".to_string(), "8".to_string()),
            super::split_cidr(&"127.0.0.1/8".to_string()).unwrap()
        );
    }

    #[test]
    fn test_split_cidr_invalid_range() {
        assert_eq!(
            "Invalid range: 129".to_string(),
            super::split_cidr(&"127.0.0.1/129".to_string()).unwrap_err()
        );
    }

    #[test]
    fn test_convert_ipv4_addr_str_to_unsigned_integer_valid() {
        assert_eq!(
            2130706433,
            super::convert_ip_addr_str_to_unsigned_integer("127.0.0.1").unwrap()
        );
    }

    #[test]
    fn test_convert_ipv4_addr_str_to_unsigned_integer_invalid() {
        assert_eq!(
            "invalid IP address syntax".to_string(),
            super::convert_ip_addr_str_to_unsigned_integer("invalid")
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn test_convert_ipv6_addr_str_to_unsigned_integer_valid() {
        assert_eq!(
            1,
            super::convert_ip_addr_str_to_unsigned_integer("::1").unwrap()
        );
    }

    #[test]
    fn test_convert_range_str_to_bit_mask_valid() {
        assert_eq!(
            0b11111111u128,
            super::convert_range_str_to_bit_mask("8").unwrap()
        );
    }

    #[test]
    fn test_convert_range_str_to_bit_mask_invalid() {
        assert_eq!(
            "Invalid range: 129".to_string(),
            super::convert_range_str_to_bit_mask("129").unwrap_err()
        );
    }
}
