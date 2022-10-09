//! Module for handling networking relevant to filtering, such as determining if a IP address falls within a networking range

use std::net::IpAddr;

const MAX_BIT_MASK_SIZE: u32 = 128; // IPv6 128 Bit
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
            if (num > MAX_BIT_MASK_SIZE) {
                return Err(format!("Invalid range: {}", num));
            }
        }
        Err(err) => return Err("Cidr is not numeric".to_string()),
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
            if (num > MAX_BIT_MASK_SIZE) {
                return Err(format!("Invalid range: {}", num));
            }
            num
        }
        Err(err) => return Err("Cidr is not numeric".to_string()),
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
