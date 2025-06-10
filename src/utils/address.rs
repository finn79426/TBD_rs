use bitcoin::Address as BitcoinAddress;
use bitcoin::Network as BitcoinNetwork;
use bs58;
use hex;
use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::str::FromStr;

static REGEX_P2PKH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^1[1-9A-HJ-NP-Za-km-z]{25,34}$").unwrap());
static REGEX_P2SH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^3[1-9A-HJ-NP-Za-km-z]{25,34}$").unwrap());
static REGEX_BECH32: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(bc1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,59}$").unwrap());
static REGEX_ETH: Lazy<Regex> = Lazy::new(|| Regex::new(r"^0x[0-9a-fA-F]{40}$").unwrap());
static REGEX_TRON: Lazy<Regex> = Lazy::new(|| Regex::new(r"^T[1-9A-HJ-NP-Za-km-z]{33}$").unwrap());

#[derive(Debug, PartialEq)]
pub enum Network {
    BITCOIN,
    ETHEREUM,
    TRON,
}

pub fn identify(address: &str) -> Option<Network> {
    match address {
        addr if is_bitcoin(addr) => Some(Network::BITCOIN),
        addr if is_ethereum(addr) => Some(Network::ETHEREUM),
        addr if is_tron(addr) => Some(Network::TRON),
        _ => None,
    }
}

pub fn eth_to_tron(address: &str) -> Result<String, String> {
    if !is_ethereum(address) {
        return Err("not a valid ethereum address".to_string());
    }

    let addr = address.strip_prefix("0x").unwrap_or(address);

    let addr = if addr.len() > 40 {
        let offset = addr.len() - 40;
        &addr[offset..]
    } else {
        addr
    };

    debug_assert_eq!(addr.len(), 40);

    let tron_hex = format!("41{}", addr);
    let tron_bytes = hex::decode(&tron_hex).unwrap();

    let checksum = {
        let first_hash = Sha256::digest(&tron_bytes);
        let second_hash = Sha256::digest(&first_hash);
        second_hash[..4].to_vec()
    };

    let tron_addr = bs58::encode([tron_bytes, checksum].concat()).into_string();

    debug_assert!(tron_addr.starts_with("T"));
    debug_assert!(tron_addr.len() == 34);
    debug_assert!(is_tron(&tron_addr));

    Ok(tron_addr)
}

pub fn tron_to_eth(address: &str) -> Result<String, String> {
    if !is_tron(address) {
        return Err("not a valid tron address".to_string());
    }

    let decoded = bs58::decode(address).into_vec().unwrap();
    let body = &decoded[1..21];
    let eth_body = hex::encode(body);
    let eth_addr = to_checksum(&eth_body).unwrap();

    debug_assert!(eth_addr.starts_with("0x"));
    debug_assert!(eth_addr.len() == 42);
    debug_assert!(is_ethereum(&eth_addr));

    Ok(eth_addr)
}

pub fn to_checksum(address: &str) -> Result<String, String> {
    if !is_ethereum(address) {
        return Err("not a valid ethereum address".to_string());
    }

    let addr = address.strip_prefix("0x").unwrap_or(address);

    let addr = if addr.len() > 40 {
        let offset = addr.len() - 40;
        &addr[offset..]
    } else {
        addr
    };

    debug_assert!(addr.len() == 40);

    let addr_lower = addr.to_lowercase();
    let hash = Keccak256::digest(addr_lower.as_bytes());

    let mut checksum_addr = String::from("0x");

    for (i, c) in addr_lower.chars().enumerate() {
        let hash_byte = hash[i / 2];
        let hash_nibble = if i % 2 == 0 {
            (hash_byte >> 4) & 0xF
        } else {
            hash_byte & 0xF
        };
        if c.is_digit(10) {
            checksum_addr.push(c);
        } else if hash_nibble >= 8 {
            checksum_addr.push(c.to_ascii_uppercase());
        } else {
            checksum_addr.push(c);
        }
    }

    debug_assert!(checksum_addr.starts_with("0x"));
    debug_assert!(checksum_addr.len() == 42);
    debug_assert!(is_ethereum(&checksum_addr));

    Ok(checksum_addr)
}

pub fn is_bitcoin(address: &str) -> bool {
    if !(REGEX_P2PKH.is_match(address)
        || REGEX_P2SH.is_match(address)
        || REGEX_BECH32.is_match(address))
    {
        return false;
    }

    match BitcoinAddress::from_str(address) {
        Ok(addr) => addr.require_network(BitcoinNetwork::Bitcoin).is_ok(),
        Err(_) => false,
    }
}

pub fn is_ethereum(address: &str) -> bool {
    let addr = address.strip_prefix("0x").unwrap_or(address);

    let addr = match addr.len() {
        len if len < 40 => return false,
        len if len > 40 => {
            // remove padded zeros
            let offset = len - 40;
            if addr[..offset].chars().all(|c| c == '0') {
                format!("0x{}", &addr[offset..])
            } else {
                return false;
            }
        }
        _ => format!("0x{}", addr),
    };

    debug_assert!(addr.len() == 42);
    debug_assert!(addr.starts_with("0x"));

    REGEX_ETH.is_match(&addr)
}

pub fn is_tron(address: &str) -> bool {
    if !REGEX_TRON.is_match(address) {
        return false;
    }

    debug_assert!(address.starts_with("T"));
    debug_assert!(address.len() == 34);

    let decoded = match bs58::decode(address).into_vec() {
        Ok(vec) => vec,
        Err(_) => return false,
    };

    if decoded.len() != 25 {
        return false;
    }

    let (body, checksum) = decoded.split_at(21);
    let hash = Sha256::digest(&Sha256::digest(body));
    let expected_checksum = &hash[..4];

    expected_checksum == checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify() {
        assert_eq!(
            identify("1DFGekrfqNNWGL7Gw7BW2pvYpZVRNmmg18"),
            Some(Network::BITCOIN)
        );
        assert_eq!(
            identify("39kz54D6ewchz3sXvncHjFYpcNGUrZ11Te"),
            Some(Network::BITCOIN)
        );
        assert_eq!(
            identify("bc1qgll00eher0sferr6d5xsa9puxv8ez0z76xquyp"),
            Some(Network::BITCOIN)
        );
        assert_eq!(
            identify("bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65"),
            Some(Network::BITCOIN)
        );
        assert_eq!(
            identify("bc1p7gdx38p6n0xngzv4p8vjmu2e70ym0w9anwxxs7s6fpn7zjm0rwvsuugdey"),
            Some(Network::BITCOIN)
        );
        assert_eq!(
            identify("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
            Some(Network::ETHEREUM)
        );
        assert_eq!(
            identify("0x000000000000000000000000dAC17F958D2ee523a2206206994597C13D831ec7"),
            Some(Network::ETHEREUM)
        );
        assert_eq!(
            identify("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
            Some(Network::TRON)
        );

        assert_eq!(identify("hello world"), None);
        assert_eq!(identify("1234567890"), None);
        assert_eq!(identify("1notarealaddressatall"), None);
        assert_eq!(identify("3notarealaddressatall"), None);
        assert_eq!(identify("bc1qnotarealaddressatall"), None);
        assert_eq!(identify("bc1pnotarealaddressatall"), None);
        assert_eq!(identify("Tnotarealaddressatall"), None);
        assert_eq!(identify(""), None);
    }

    #[test]
    fn test_eth_to_tron() {
        assert_eq!(
            eth_to_tron("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
            Ok("TVut7P3Wnem9TFcSAjow2WGETKFBs5CMyj".to_string())
        ); // checksum
        assert_eq!(
            eth_to_tron("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            Ok("TVut7P3Wnem9TFcSAjow2WGETKFBs5CMyj".to_string())
        ); // all lower
        assert_eq!(
            eth_to_tron("0xDAC17F958D2EE523A2206206994597C13D831EC7"),
            Ok("TVut7P3Wnem9TFcSAjow2WGETKFBs5CMyj".to_string())
        ); // all upper
        assert_eq!(
            eth_to_tron("0x000000000000000000000000dAC17F958D2ee523a2206206994597C13D831ec7"),
            Ok("TVut7P3Wnem9TFcSAjow2WGETKFBs5CMyj".to_string())
        ); // allow full 32 bytes
        assert_eq!(
            eth_to_tron("0x0000000000000000000000000000000000000000000000000000000000000000"),
            Ok("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb".to_string())
        ); // allow pre-compile address
        assert_eq!(
            eth_to_tron("0x0000000000000000000000000000000000000000000000000000000000000001"),
            Ok("T9yD14Nj9j7xAB4dbGeiX9h8unkKLxmGkn".to_string())
        ); // allow pre-compile address
        assert_eq!(
            eth_to_tron("0x000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            Ok("TXka46PPwttNPWfFDPtt3GUodbPThyufaV".to_string())
        ); // allow pre-compile address

        assert_eq!(
            eth_to_tron("hello world"),
            Err("not a valid ethereum address".to_string())
        ); // text string
        assert_eq!(
            eth_to_tron("1234567890"),
            Err("not a valid ethereum address".to_string())
        ); // decimal string
        assert_eq!(
            eth_to_tron("0xnotarealaddressatall"),
            Err("not a valid ethereum address".to_string())
        ); // not a related address
        assert_eq!(
            eth_to_tron(""),
            Err("not a valid ethereum address".to_string())
        ); // empty string
    }

    #[test]
    fn test_tron_to_eth() {
        assert_eq!(
            tron_to_eth("TVut7P3Wnem9TFcSAjow2WGETKFBs5CMyj"),
            Ok("0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string())
        );

        assert_eq!(
            tron_to_eth("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj7t"),
            Err("not a valid tron address".to_string())
        ); // invalid checksum
        assert_eq!(
            tron_to_eth("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLjuu"),
            Err("not a valid tron address".to_string())
        ); // invalid last char
        assert_eq!(
            tron_to_eth("SR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
            Err("not a valid tron address".to_string())
        ); // invalid prefix
        assert_eq!(
            tron_to_eth("TR7NHqjeKQxGTCi8qZZZY4pL8otSzgjLj6t"),
            Err("not a valid tron address".to_string())
        ); // invalid middle char
        assert_eq!(
            tron_to_eth("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjL"),
            Err("not a valid tron address".to_string())
        ); // length too short
        assert_eq!(
            tron_to_eth("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6tt"),
            Err("not a valid tron address".to_string())
        ); // length too long
        assert_eq!(
            tron_to_eth("TR7NHqjeKQxGTCi8q8ZY4pL0otSzgjLj6t"),
            Err("not a valid tron address".to_string())
        ); // invalid char '0'
    }

    #[test]
    fn test_to_checksum() {
        assert_eq!(
            to_checksum("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
            Ok("0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string())
        ); // checksum
        assert_eq!(
            to_checksum("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            Ok("0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string())
        ); // lower
        assert_eq!(
            to_checksum("0xDAC17F958D2EE523A2206206994597C13D831EC7"),
            Ok("0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string())
        ); // upper
        assert_eq!(
            to_checksum("dAC17F958D2ee523a2206206994597C13D831ec7"),
            Ok("0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string())
        ); // without prefix
        assert_eq!(
            to_checksum("0x000000000000000000000000dAC17F958D2ee523a2206206994597C13D831ec7"),
            Ok("0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string())
        ); // padding zeros
        assert_eq!(
            to_checksum("000000000000000000000000dAC17F958D2ee523a2206206994597C13D831ec7"),
            Ok("0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string())
        ); // padding zeros without prefix
        assert_eq!(
            to_checksum("0x0000000000000000000000000000000000000000000000000000000000000000"),
            Ok("0x0000000000000000000000000000000000000000".to_string())
        ); // pre-compile address
        assert_eq!(
            to_checksum("0x0000000000000000000000000000000000000000000000000000000000000001"),
            Ok("0x0000000000000000000000000000000000000001".to_string())
        ); // pre-compile address
        assert_eq!(
            to_checksum("0x000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            Ok("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE".to_string())
        ); // pre-compile address

        assert_eq!(
            to_checksum("hello world"),
            Err("not a valid ethereum address".to_string())
        ); // text string
        assert_eq!(
            to_checksum("1234567890"),
            Err("not a valid ethereum address".to_string())
        ); // decimal string
        assert_eq!(
            to_checksum("0xnotarealaddressatall"),
            Err("not a valid ethereum address".to_string())
        ); // not a related address
        assert_eq!(
            to_checksum(""),
            Err("not a valid ethereum address".to_string())
        ); // empty string
    }

    #[test]
    fn test_is_bitcoin() {
        assert!(is_bitcoin("1DFGekrfqNNWGL7Gw7BW2pvYpZVRNmmg18")); // P2PKH
        assert!(is_bitcoin("39kz54D6ewchz3sXvncHjFYpcNGUrZ11Te")); // P2SH
        assert!(is_bitcoin("bc1qgll00eher0sferr6d5xsa9puxv8ez0z76xquyp")); // P2WPKH
        assert!(is_bitcoin(
            "bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65"
        )); // P2WSH
        assert!(is_bitcoin(
            "bc1p7gdx38p6n0xngzv4p8vjmu2e70ym0w9anwxxs7s6fpn7zjm0rwvsuugdey"
        )); // P2TR

        assert!(!is_bitcoin("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfN9")); // P2PKH invalid checksum
        assert!(!is_bitcoin("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNL9")); // P2SH invalid checksum
        assert!(!is_bitcoin("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt081")); // P2WPKH invalid checksum
        assert!(!is_bitcoin("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4n0a9muf4")); // P2WSH invalid checksum
        assert!(!is_bitcoin(
            "bc1p5cyxnuxmeuwuvkwfem96l0gdku6zkszt5v8a8h3u6d6c6r8s5w7qz6v7x0b"
        )); // P2TR invalid checksum

        assert!(!is_bitcoin("1DFGekrfqNNWGL7Gw7BW2pvYpZVRNmmg1")); // P2PKH too short
        assert!(!is_bitcoin("1DFGekrfqNNWGL7Gw7BW2pvYpZVRNmmg1O")); // P2PKH invalid char 'O'
        assert!(!is_bitcoin("39kz54D6ewchz3sXvncHjFYpcNGUrZ11T")); // P2SH too short
        assert!(!is_bitcoin("39kz54D6ewchz3sXvncHjFYpcNGUrZ11TeI")); // P2SH invalid char 'I'
        assert!(!is_bitcoin("bc1qgll00eher0sferr6d5xsa9puxv8ez0z76xquy")); // P2WPKH too short
        assert!(!is_bitcoin("bc1qgll00eher0sferr6d5xsa9puxv8ez0z76xquyP")); // P2WPKH disallow uppercase
        assert!(!is_bitcoin(
            "bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz6"
        )); // P2WSH too short
        assert!(!is_bitcoin(
            "bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz6O"
        )); // P2WSH invalid char 'O'
        assert!(!is_bitcoin(
            "bc1p7gdx38p6n0xngzv4p8vjmu2e70ym0w9anwxxs7s6fpn7zjm0rwvsuugde"
        )); // P2TR too short
        assert!(!is_bitcoin(
            "bc1p7gdx38p6n0xngzv4p8vjmu2e70ym0w9anwxxs7s6fpn7zjm0rwvsuugdeO"
        )); // P2TR invalid char 'O'

        assert!(!is_bitcoin("hello world")); // text string
        assert!(!is_bitcoin("1234567890")); // decimal string
        assert!(!is_bitcoin("1notarealaddressatall")); // not a related address
        assert!(!is_bitcoin("3notarealaddressatall")); // not a related address
        assert!(!is_bitcoin("bc1qnotarealaddressatall")); // not a related address
        assert!(!is_bitcoin("bc1pnotarealaddressatall")); // not a related address
        assert!(!is_bitcoin("")); // empty string
    }

    #[test]
    fn test_is_ethereum() {
        assert!(is_ethereum("0xdAC17F958D2ee523a2206206994597C13D831ec7")); // checksum
        assert!(is_ethereum("0xdac17f958d2ee523a2206206994597c13d831ec7")); // all lower
        assert!(is_ethereum("0xDAC17F958D2EE523A2206206994597C13D831EC7")); // all upper
        assert!(is_ethereum(
            "0x000000000000000000000000dAC17F958D2ee523a2206206994597C13D831ec7"
        )); // allow full 32 bytes
        assert!(is_ethereum(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        )); // allow pre-compile address
        assert!(is_ethereum(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        )); // allow pre-compile address
        assert!(is_ethereum(
            "0x000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        )); // allow pre-compile address

        assert!(!is_ethereum("0xdAC17F958D2ee523a2206206994597C13D831ecG")); // invalid hex char G
        assert!(!is_ethereum("dAC17F958D2ee523a2206206994597C13D831ecG")); // missing 0x
        assert!(!is_ethereum("0xdAC17F958D2ee523a2206206994597C13D831ec")); // 41 chars
        assert!(!is_ethereum("0xfdAC17F958D2ee523a2206206994597C13D831ec7")); // 43 chars (MSB not starts with '0')

        assert!(!is_ethereum("hello world")); // text string
        assert!(!is_ethereum("1234567890")); // decimal string
        assert!(!is_ethereum("0xnotarealaddressatall")); // not a related address
        assert!(!is_ethereum("")); // empty string
    }

    #[test]
    fn test_is_tron() {
        assert!(is_tron("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")); // valid

        assert!(!is_tron("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj7t")); // invalid checksum
        assert!(!is_tron("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLjuu")); // invalid last char
        assert!(!is_tron("SR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")); // invalid prefix
        assert!(!is_tron("TR7NHqjeKQxGTCi8qZZZY4pL8otSzgjLj6t")); // invalid middle char
        assert!(!is_tron("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjL")); // length too short
        assert!(!is_tron("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6tt")); // length too long
        assert!(!is_tron("TR7NHqjeKQxGTCi8q8ZY4pL0otSzgjLj6t")); // invalid char '0'

        assert!(!is_tron("hello world")); // text string
        assert!(!is_tron("1234567890")); // decimal string
        assert!(!is_tron("Tnotarealaddressatall")); // not a related address
        assert!(!is_tron("")); // empty string
    }
}
