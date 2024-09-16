use ipnetwork::IpNetwork;
use std::net::Ipv4Addr;

pub fn get_ipv4_addresses(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    if let Ok(cidr) = input.parse::<IpNetwork>() {
        match cidr {
            IpNetwork::V4(network) => Ok(network.iter().collect()),
            IpNetwork::V6(_) => Err("IPv6 range is not supported".to_string()),
        }
    } else if let Ok(ip) = input.parse::<Ipv4Addr>() {
        Ok(vec![ip])
    } else {
        Err(format!("Invalid IP or CIDR notation:{}", input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_single_ip() {
        let input = "192.168.1.1";
        let result = get_ipv4_addresses(input).unwrap();
        let expected = vec!["192.168.1.1".parse::<Ipv4Addr>().unwrap()];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_ip_range() {
        let input = "192.168.1.0/30";
        let result = get_ipv4_addresses(input).unwrap();
        let expected: Vec<Ipv4Addr> = vec![
            "192.168.1.0".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            "192.168.1.3".parse().unwrap(),
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_invalid_ip() {
        let input = "999.999.999.999";
        let result = get_ipv4_addresses(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_cidr() {
        let input = "192.168.1.0/33";
        let result = get_ipv4_addresses(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_not_supported() {
        let input = "2001:db8::/32";
        let result = get_ipv4_addresses(input);
        assert_eq!(result, Err("IPv6 range is not supported".to_string()));
    }
}
