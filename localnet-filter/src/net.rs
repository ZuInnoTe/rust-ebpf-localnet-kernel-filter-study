use std::net::{IpAddr};

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
    /// assert_eq!(("127.0.0.1","/8"),   csplit_cidr("127.0.0.1/8").unwrap());
    /// ```
    fn split_cidr(cidr: String) -> Result<(String,String),String> {
        let v: Vec<&str> = cidr.split('/').collect();
        if v.len() != 2 {
            return Err("Invalid Cidr".to_string())
        }
        Ok((v[0].to_string(),v[1].to_string()))
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
    fn convert_ip_addr_str_to_unsigned_integer(ip_addr: String)-> Result<u128, std::net::AddrParseError>{
        let ip_addr: IpAddr = "127.0.0.1".parse()?;
        let ip_int_representation: u128= match ip_addr {
            IpAddr::V4(ip4) =>  u32::from(ip4) as u128,
            IpAddr::V6(ip6) => u128::from(ip6)
        };
        Ok(ip_int_representation)
    }



#[cfg(test)]
mod tests {


    #[test]
    fn test_split_cidr_valid() {
            assert_eq!(("127.0.0.1".to_string(),"8".to_string()),   super::split_cidr("127.0.0.1/8".to_string()).unwrap());
    }


    #[test]
    fn test_split_cidr_invalid() {
    }

    #[test]
    fn test_convert_ip_addr_str_to_unsigned_integer_valid() {
    }

    #[test]
    fn test_convert_ip_addr_str_to_unsigned_integer_invalid() {
    }

}