//! IPv6 policy and Ethernet framing for routed L3 netkit VM endpoints.

use crate::ipv6_in_prefix;

/// Map values contain no padding and use network byte order for addresses.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpNetConfig {
    pub delegated: [u8; 16],
    pub prefix_len: u32,
    pub socket_key: u32,
    pub guest_mac: [u8; 6],
    pub reserved: [u8; 2],
}

#[cfg(feature = "user")]
// SAFETY: repr(C), 32 initialized bytes, integer fields, no padding.
unsafe impl aya::Pod for XdpNetConfig {}

/// Only untagged IPv6 unicast from a non-local source enters this path.
#[inline(always)]
pub fn ipv6_unicast(frame: &[u8; 54]) -> bool {
    let source: [u8; 16] = frame[22..38].try_into().unwrap();
    frame[12] == 0x86
        && frame[13] == 0xdd
        && frame[14] >> 4 == 6
        && source != [0; 16]
        && source != core::net::Ipv6Addr::LOCALHOST.octets()
        && source[0] != 0xff
        && frame[38] != 0xff
}

impl XdpNetConfig {
    /// The primary passes valid guest sources to routing and nftables.
    #[inline(always)]
    pub fn permits_transmit(&self, frame: &[u8; 54]) -> bool {
        ipv6_unicast(frame)
            && ipv6_in_prefix(
                frame[22..38].try_into().unwrap(),
                &self.delegated,
                self.prefix_len,
            )
    }

    /// The peer receives only packets routed to this VM's delegated prefix.
    /// Routing and the namespace's forwarding policy precede this hook.
    #[inline(always)]
    pub fn permits_receive(&self, frame: &[u8; 54]) -> bool {
        ipv6_unicast(frame)
            && ipv6_in_prefix(
                frame[38..54].try_into().unwrap(),
                &self.delegated,
                self.prefix_len,
            )
            && !ipv6_in_prefix(
                frame[22..38].try_into().unwrap(),
                &self.delegated,
                self.prefix_len,
            )
    }

    /// Netkit has no Ethernet address. Its zero address is the guest gateway.
    #[inline(always)]
    pub fn frame_for_guest(&self, frame: &mut [u8; 54]) {
        frame[..6].copy_from_slice(&self.guest_mac);
        frame[6..12].fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(source: &str, destination: &str) -> [u8; 54] {
        let mut frame = [0; 54];
        frame[12..15].copy_from_slice(&[0x86, 0xdd, 0x60]);
        frame[22..38].copy_from_slice(
            &source.parse::<core::net::Ipv6Addr>().unwrap().octets(),
        );
        frame[38..54].copy_from_slice(
            &destination.parse::<core::net::Ipv6Addr>().unwrap().octets(),
        );
        frame
    }

    fn config() -> XdpNetConfig {
        XdpNetConfig {
            delegated: "fd00:ae::1200"
                .parse::<core::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            prefix_len: 120,
            socket_key: 17,
            guest_mac: [2, 3, 4, 5, 6, 7],
            reserved: [0; 2],
        }
    }

    #[test]
    fn source_ownership_and_selective_delivery_cover_prefix_edges() {
        let cfg = config();
        for address in ["fd00:ae::1200", "fd00:ae::12ff"] {
            assert!(cfg.permits_transmit(&frame(address, "2001:db8::9")));
            assert!(cfg.permits_receive(&frame("2001:db8::9", address)));
        }
        for address in ["fd00:ae::11ff", "fd00:ae::1300", "fd00:ae::1"] {
            assert!(!cfg.permits_transmit(&frame(address, "2001:db8::9")));
            assert!(!cfg.permits_receive(&frame("2001:db8::9", address)));
        }
        for source in ["::", "::1", "ff02::1", "fd00:ae::1201"] {
            assert!(!cfg.permits_receive(&frame(source, "fd00:ae::1205")));
        }
        let mut exact = cfg;
        exact.prefix_len = 128;
        assert!(exact.permits_transmit(&frame("fd00:ae::1200", "2001:db8::9")));
        assert!(
            !exact.permits_transmit(&frame("fd00:ae::1201", "2001:db8::9"))
        );
    }

    #[test]
    fn framing_changes_only_ethernet_addresses() {
        let cfg = config();
        let mut packet = frame("2001:db8::9", "fd00:ae::1205");
        packet[..12].fill(0xa5);
        let original = packet;
        cfg.frame_for_guest(&mut packet);
        assert_eq!(&packet[..6], &[2, 3, 4, 5, 6, 7]);
        assert_eq!(&packet[6..12], &[0; 6]);
        assert_eq!(&packet[12..], &original[12..]);
        assert_eq!(core::mem::size_of::<XdpNetConfig>(), 32);
    }

    #[test]
    fn other_protocols_and_multicast_fail_closed() {
        let cfg = config();
        let valid = frame("fd00:ae::1201", "2001:db8::9");
        for (offset, value) in [(12, 0x08), (13, 0), (14, 0x40), (38, 0xff)] {
            let mut packet = valid;
            packet[offset] = value;
            assert!(!cfg.permits_transmit(&packet));
        }
    }
}
