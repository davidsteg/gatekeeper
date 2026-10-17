//! `X-Real-IP` from a trusted proxy (port of `realip.py`).
//!
//! uvicorn's own proxy-headers support read `X-Forwarded-For` only. nginx's
//! common `proxy_set_header X-Real-IP $remote_addr;` setups, and some
//! ingress controllers, send `X-Real-IP` instead, and the client address
//! then stays the proxy's own. This fills that gap with the same trust
//! list: the header counts only when the immediate peer is a trusted proxy,
//! and only when no `X-Forwarded-For` came along, so the two never disagree
//! about who called.
//!
//! Plain functions over headers and a peer address; the HTTP middleware
//! wiring lives with the server.

use std::net::{IpAddr, Ipv4Addr};

use http::HeaderMap;
use ipnet::IpNet;

/// uvicorn's own default when `forwarded_allow_ips` is unset.
pub const DEFAULT_TRUSTED: &[&str] = &["127.0.0.1"];

/// The parsed trust list (`--trusted-proxies`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedProxies {
    pub trust_all: bool,
    pub networks: Vec<IpNet>,
}

impl TrustedProxies {
    /// `_parse(entries)`: `None` means the default list. `"*"` trusts every
    /// peer. Entries that are not networks (uvicorn also accepts a literal
    /// host such as a unix socket path) are skipped -- neither can be the
    /// peer of a TCP request with a header.
    pub fn parse<S: AsRef<str>>(entries: Option<&[S]>) -> TrustedProxies {
        let owned: Vec<String> = match entries {
            Some(list) => list.iter().map(|s| s.as_ref().to_string()).collect(),
            None => DEFAULT_TRUSTED.iter().map(|s| s.to_string()).collect(),
        };
        let mut networks = Vec::new();
        for entry in &owned {
            if entry == "*" {
                return TrustedProxies { trust_all: true, networks: Vec::new() };
            }
            if let Some(net) = ip_network(entry) {
                networks.push(net);
            }
        }
        TrustedProxies { trust_all: false, networks }
    }

    /// Is the peer `host` a trusted proxy?
    pub fn is_trusted(&self, host: &str) -> bool {
        if self.trust_all {
            return true;
        }
        match ip_address(host) {
            Some(address) => self.networks.iter().any(|net| net.contains(&address)),
            None => false,
        }
    }
}

/// `ipaddress.ip_address(value)`.
///
/// PORT NOTE: Python also accepts an IPv6 zone suffix (`fe80::1%eth0`);
/// `std` does not, so such a header is ignored here.
pub fn ip_address(value: &str) -> Option<IpAddr> {
    value.parse::<IpAddr>().ok()
}

/// `ipaddress.ip_network(entry, strict=False)`: an address, `addr/prefix`,
/// or (IPv4) `addr/netmask` / `addr/hostmask`. Host bits are cleared.
pub fn ip_network(entry: &str) -> Option<IpNet> {
    let mut parts = entry.split('/');
    let addr_part = parts.next()?;
    let mask_part = parts.next();
    if parts.next().is_some() {
        return None;
    }
    let addr: IpAddr = addr_part.parse().ok()?;
    let max = match addr {
        IpAddr::V4(_) => 32u8,
        IpAddr::V6(_) => 128u8,
    };
    let prefix = match mask_part {
        None => max,
        Some(m) if !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()) => {
            let n: u32 = m.parse().ok()?;
            if n > max as u32 {
                return None;
            }
            n as u8
        }
        Some(m) => match addr {
            IpAddr::V4(_) => ipv4_mask_prefix(m.parse::<Ipv4Addr>().ok()?)?,
            IpAddr::V6(_) => return None,
        },
    };
    IpNet::new(addr, prefix).ok().map(|n| n.trunc())
}

/// Prefix length of a netmask (`255.255.0.0`) or hostmask (`0.0.255.255`).
fn ipv4_mask_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    if bits.checked_shl(ones).unwrap_or(0) == 0 {
        return Some(ones as u8);
    }
    let inverted = !bits;
    let ones = inverted.leading_ones();
    if inverted.checked_shl(ones).unwrap_or(0) == 0 {
        return Some(ones as u8);
    }
    None
}

/// Python's `str.isspace()` for one character.
fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// The last value of header `name`, decoded as latin-1 (Python's
/// `dict(scope["headers"])` keeps the last duplicate).
fn last_header_latin1(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(name)
        .iter()
        .last()
        .map(|v| v.as_bytes().iter().map(|&b| b as char).collect())
}

/// The address `X-Real-IP` names, when it counts: non-empty, no
/// `X-Forwarded-For` alongside it, a trusted peer, and a valid IP address.
/// `None` means "keep the peer address as it is".
pub fn real_ip(trusted: &TrustedProxies, peer_host: Option<&str>, headers: &HeaderMap) -> Option<String> {
    let real = last_header_latin1(headers, "x-real-ip").unwrap_or_default();
    let real = real.trim_matches(py_isspace).to_string();
    // uvicorn-style X-Forwarded-For handling has already run when it was
    // sent, and the peer may by now be the forwarded address: leave it be.
    if real.is_empty() || headers.contains_key("x-forwarded-for") {
        return None;
    }
    let peer = peer_host?;
    if !trusted.is_trusted(peer) || ip_address(&real).is_none() {
        return None;
    }
    Some(real)
}

/// The client host a request is attributed to: the `X-Real-IP` address when
/// it counts, otherwise the peer's own (port 0 in Python's rewritten scope).
pub fn client_host(trusted: &TrustedProxies, peer_host: Option<&str>, headers: &HeaderMap) -> Option<String> {
    real_ip(trusted, peer_host, headers).or_else(|| peer_host.map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(trusted: Option<&[&str]>, peer: &str, headers: &[(&str, &str)]) -> String {
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.append(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        client_host(&TrustedProxies::parse(trusted), Some(peer), &map).unwrap()
    }

    #[test]
    fn x_real_ip_counts_only_from_a_trusted_proxy() {
        let cidr: &[&str] = &["172.16.0.0/12"];
        let all: &[&str] = &["*"];
        // A trusted proxy's X-Real-IP names the caller.
        assert_eq!(seen(Some(cidr), "172.16.29.1", &[("x-real-ip", "10.10.110.102")]), "10.10.110.102");
        assert_eq!(seen(Some(all), "172.16.29.1", &[("x-real-ip", "10.10.110.102")]), "10.10.110.102");
        // Anyone else's is ignored, so a caller cannot pick its own address.
        assert_eq!(seen(Some(cidr), "10.10.110.7", &[("x-real-ip", "1.2.3.4")]), "10.10.110.7");
        // Unset means uvicorn's default: only 127.0.0.1.
        assert_eq!(seen(None, "172.16.29.1", &[("x-real-ip", "1.2.3.4")]), "172.16.29.1");
        assert_eq!(seen(None, "127.0.0.1", &[("x-real-ip", "1.2.3.4")]), "1.2.3.4");
        // X-Forwarded-For, already applied, wins.
        assert_eq!(
            seen(Some(all), "10.10.110.102", &[("x-forwarded-for", "10.10.110.102"), ("x-real-ip", "1.2.3.4")]),
            "10.10.110.102"
        );
        // Not an address: ignored.
        assert_eq!(seen(Some(all), "172.16.29.1", &[("x-real-ip", "<script>")]), "172.16.29.1");
        // Whitespace is stripped; the last duplicate wins.
        assert_eq!(seen(None, "127.0.0.1", &[("x-real-ip", " 1.2.3.4 ")]), "1.2.3.4");
        assert_eq!(seen(None, "127.0.0.1", &[("x-real-ip", "1.1.1.1"), ("x-real-ip", "2.2.2.2")]), "2.2.2.2");
    }

    #[test]
    fn networks_parse_like_ipaddress() {
        assert_eq!(ip_network("10.1.2.3/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(ip_network("10.0.0.0/255.0.0.0").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(ip_network("10.0.0.0/0.0.0.255").unwrap().to_string(), "10.0.0.0/24");
        assert_eq!(ip_network("::1").unwrap().to_string(), "::1/128");
        assert!(ip_network("10.0.0.0/33").is_none());
        assert!(ip_network("/run/proxy.sock").is_none());
        assert!(ip_network("10.0.0.0/255.0.255.0").is_none());
        let t = TrustedProxies::parse(Some(&["unix:/x", "::1"]));
        assert!(t.is_trusted("::1"));
        assert!(!t.is_trusted("127.0.0.1"));
        assert!(!t.is_trusted("not-an-ip"));
    }
}
