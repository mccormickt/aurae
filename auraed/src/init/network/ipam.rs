/* -------------------------------------------------------------------------- *\
 *                |   █████╗ ██╗   ██╗██████╗  █████╗ ███████╗ |              *
 *                |  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝ |              *
 *                |  ███████║██║   ██║██████╔╝███████║█████╗   |              *
 *                |  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══╝   |              *
 *                |  ██║  ██║╚██████╔╝██║  ██║██║  ██║███████╗ |              *
 *                |  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |              *
 *                +--------------------------------------------+              *
 *                                                                            *
 *                         Distributed Systems Runtime                        *
 * -------------------------------------------------------------------------- *
 * Copyright 2022 - 2024, the aurae contributors                              *
 * SPDX-License-Identifier: Apache-2.0                                        *
\* -------------------------------------------------------------------------- */

//! IPv6 IP Address Management (IPAM)
//!
//! Allocates and releases IPv6 prefix delegations keyed on opaque
//! string identifiers. The host gateway is shared at `pool_base+1` for
//! every allocation; `/128` host addresses on multiple endpoints
//! work because each endpoint sits on its own L3 link with no shared
//! L2 segment, so there's no neighbor-discovery conflict.
//!
//! The block walker is built on top of [`ipnet::Ipv6Net::subnets`], which
//! iterates the configured pool as a stream of `device_prefix`-sized
//! subnets. Allocation is "take the next subnet that doesn't include the
//! host slot". Release pushes the subnet back onto a reuse stack.
//!
//! Construction-time errors flow through the shared [`ValidationError`]
//! type. Runtime allocator errors stay in [`IpamError`].

use ipnet::Ipv6Net;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use thiserror::Error;
use validation::ValidationError;

/// Default ULA pool: fd00:ae::/64 ("ae" = aurae)
pub const DEFAULT_POOL_V6: &str = "fd00:ae::/64";

/// Default device prefix size for IPv6: /128 — single address per device.
pub const DEFAULT_DEVICE_PREFIX_V6: u8 = 128;

/// Runtime errors from the IPAM allocator. Construction-time errors (parse,
/// prefix range) live in [`ValidationError`] instead.
#[derive(Debug, Error)]
pub enum IpamError {
    #[error("address already allocated for '{0}'")]
    AlreadyAllocated(String),

    #[error("no allocation found for '{0}'")]
    NotAllocated(String),

    #[error("address pool exhausted")]
    PoolExhausted,
}

pub type Result<T> = std::result::Result<T, IpamError>;

/// Configuration for the IPAM system. Construct via [`IpamConfig::new`] or
/// [`IpamConfig::default`]; both enforce `pool_prefix <= device_prefix`.
#[derive(Debug, Clone)]
pub struct IpamConfig {
    pub(crate) pool_v6: Ipv6Net,
    pub(crate) device_prefix_v6: u8,
}

impl Default for IpamConfig {
    fn default() -> Self {
        Self::new(
            DEFAULT_POOL_V6.parse().expect("default v6 pool is valid"),
            DEFAULT_DEVICE_PREFIX_V6,
        )
        .expect("default IPAM config is valid")
    }
}

impl IpamConfig {
    pub fn new(
        pool_v6: Ipv6Net,
        device_prefix_v6: u8,
    ) -> std::result::Result<Self, ValidationError> {
        if device_prefix_v6 > 128 {
            return Err(ValidationError::Maximum {
                field: "device_prefix_v6".to_string(),
                maximum: "128".to_string(),
                units: "prefix bits".to_string(),
            });
        }
        if pool_v6.prefix_len() > device_prefix_v6 {
            return Err(ValidationError::Invalid {
                field: "pool_v6".to_string(),
            });
        }
        Ok(Self { pool_v6, device_prefix_v6 })
    }
}

/// Per-cell IPv6 allocation. `host_ip` is the shared endpoint-side gateway;
/// `delegated` is the prefix the guest device owns; `guest_ip` is the
/// first usable address inside `delegated` and is what the guest binds.
#[derive(Debug, Clone)]
pub struct Allocation {
    pub(crate) host_ip: Ipv6Addr,
    pub(crate) delegated: Ipv6Net,
    pub(crate) guest_ip: Ipv6Addr,
}

/// IP Address Manager.
///
/// Carves the configured pool into `device_prefix`-sized subnets via
/// `ipnet::Ipv6Net::subnets`, then hands them out in order, skipping any
/// subnet that contains the shared host slot (`pool_base + 1`).
///
/// Synchronization lives inside the type via [`std::sync::Mutex`], so
/// `Ipam` can be shared (as `&Ipam` or via embedding in another `Arc`-able
/// type) without callers needing to wrap it in their own lock. Critical
/// sections are short and never span an `await`, so a sync mutex is
/// appropriate.
#[derive(Debug)]
pub struct Ipam {
    inner: std::sync::Mutex<IpamInner>,
}

/// Allocator state. Kept in a separate struct so `Ipam` can guard it
/// behind a single `Mutex` without exposing its fields publicly.
#[derive(Debug)]
struct IpamInner {
    config: IpamConfig,
    /// Index into the `subnets()` iterator for the next allocation.
    next_block: u128,
    allocated: HashMap<String, Allocation>,
    released: Vec<u128>,
}

impl Default for Ipam {
    fn default() -> Self {
        Self::new(IpamConfig::default())
    }
}

impl Ipam {
    pub fn new(config: IpamConfig) -> Self {
        Self { inner: std::sync::Mutex::new(IpamInner::new(config)) }
    }

    pub fn allocate(&self, key: &str) -> Result<Allocation> {
        self.inner.lock().expect("ipam mutex poisoned").allocate(key)
    }

    pub fn release(&self, key: &str) -> Result<Allocation> {
        self.inner.lock().expect("ipam mutex poisoned").release(key)
    }
}

impl IpamInner {
    fn new(config: IpamConfig) -> Self {
        // First guest block: the lowest block whose addresses don't include
        // the shared host slot (pool_base + 1). With device_prefix == 128
        // (single-address blocks), block 0 is pool_base and block 1 is the
        // host — start guests at 2. With device_prefix < 128, the host slot
        // sits inside block 0 — start guests at 1.
        let next_block = if config.device_prefix_v6 == 128 { 2 } else { 1 };
        Self {
            config,
            next_block,
            allocated: HashMap::new(),
            released: Vec::new(),
        }
    }

    /// Shared v6 host gateway used on every endpoint (`pool_base + 1`).
    fn host_ip(&self) -> Ipv6Addr {
        let base = u128::from(self.config.pool_v6.network());
        Ipv6Addr::from(base.saturating_add(1))
    }

    fn allocate(&mut self, key: &str) -> Result<Allocation> {
        if self.allocated.contains_key(key) {
            return Err(IpamError::AlreadyAllocated(key.to_string()));
        }

        let block_idx = if let Some(reused) = self.released.pop() {
            reused
        } else {
            let next = self.next_block;
            self.next_block =
                next.checked_add(1).ok_or(IpamError::PoolExhausted)?;
            next
        };

        let delegated = nth_subnet(
            &self.config.pool_v6,
            self.config.device_prefix_v6,
            block_idx,
        )
        .ok_or(IpamError::PoolExhausted)?;
        let guest_ip = delegated.network();

        let allocation =
            Allocation { host_ip: self.host_ip(), delegated, guest_ip };
        let _ = self.allocated.insert(key.to_string(), allocation.clone());
        Ok(allocation)
    }

    fn release(&mut self, key: &str) -> Result<Allocation> {
        let allocation = self
            .allocated
            .remove(key)
            .ok_or_else(|| IpamError::NotAllocated(key.to_string()))?;

        let block = block_index(&self.config.pool_v6, &allocation.delegated);
        if !self.released.contains(&block) {
            self.released.push(block);
        }

        Ok(allocation)
    }
}

/// Get the `n`-th `device_prefix`-sized subnet of `pool`. Wraps
/// `Ipv6Net::subnets()` and bounds-checks via `Iterator::nth`. Returns
/// `None` when the pool isn't big enough (pool prefix > device prefix
/// is rejected at config-construction time, so failure here is purely
/// "ran past the end").
fn nth_subnet(pool: &Ipv6Net, device_prefix: u8, n: u128) -> Option<Ipv6Net> {
    let mut subnets = pool.subnets(device_prefix).ok()?;
    let n_usize: usize = n.try_into().ok()?;
    subnets.nth(n_usize)
}

/// Compute which block index `block` is within `pool` for the given
/// device prefix. Used on release to push the right index back into the
/// reuse stack. Both inputs come from our own allocator — `block` is
/// always a valid subnet of `pool` aligned on `device_prefix` bits.
fn block_index(pool: &Ipv6Net, block: &Ipv6Net) -> u128 {
    let pool_base = u128::from(pool.network());
    let block_base = u128::from(block.network());
    let block_size_bits = (128u32).saturating_sub(block.prefix_len() as u32);
    let offset = block_base.saturating_sub(pool_base);
    if block_size_bits == 0 { offset } else { offset >> block_size_bits }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_pool_and_default_prefix() {
        let config = IpamConfig::default();
        assert_eq!(config.pool_v6.to_string(), DEFAULT_POOL_V6);
        assert_eq!(config.device_prefix_v6, DEFAULT_DEVICE_PREFIX_V6);
    }

    #[test]
    fn rejects_pool_prefix_longer_than_device_prefix() {
        let v6: Ipv6Net = "fd00:ae::/96".parse().unwrap();
        let result = IpamConfig::new(v6, /* dev v6 */ 80);
        assert!(matches!(result, Err(ValidationError::Invalid { .. })));
    }

    #[test]
    fn allocates_default() {
        let ipam = Ipam::default();
        let alloc = ipam.allocate("a1").unwrap();

        // First guest is fd00:ae::2; the host gateway is the shared
        // fd00:ae::1 used on every endpoint.
        assert_eq!(
            alloc.guest_ip,
            Ipv6Addr::new(0xfd00, 0x00ae, 0, 0, 0, 0, 0, 2)
        );
        assert_eq!(
            alloc.host_ip,
            Ipv6Addr::new(0xfd00, 0x00ae, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(alloc.delegated.prefix_len(), 128);
    }

    #[test]
    fn allocations_advance_per_call_with_shared_host() {
        let ipam = Ipam::default();
        let alloc1 = ipam.allocate("a1").unwrap();
        let alloc2 = ipam.allocate("a2").unwrap();

        assert_eq!(
            alloc2.guest_ip,
            Ipv6Addr::new(0xfd00, 0x00ae, 0, 0, 0, 0, 0, 3)
        );
        assert_eq!(alloc1.host_ip, alloc2.host_ip);
    }

    #[test]
    fn host_ip_does_not_collide_with_any_guest() {
        let ipam = Ipam::default();
        let host = {
            let inner = ipam.inner.lock().unwrap();
            inner.host_ip()
        };
        for i in 0..10 {
            let alloc = ipam.allocate(&format!("a{i}")).unwrap();
            assert_ne!(alloc.guest_ip, host);
            assert_eq!(alloc.host_ip, host);
        }
    }

    #[test]
    fn duplicate_allocation_rejected() {
        let ipam = Ipam::default();
        let _ = ipam.allocate("a1").unwrap();
        assert!(matches!(
            ipam.allocate("a1"),
            Err(IpamError::AlreadyAllocated(_))
        ));
    }

    #[test]
    fn release_returns_slot_for_reuse() {
        let ipam = Ipam::default();
        let alloc1 = ipam.allocate("a1").unwrap();
        let _ = ipam.allocate("a2").unwrap();
        let _ = ipam.release("a1").unwrap();

        let alloc3 = ipam.allocate("a3").unwrap();
        assert_eq!(alloc3.guest_ip, alloc1.guest_ip);
    }

    #[test]
    fn release_unknown_key_returns_not_allocated() {
        let ipam = Ipam::default();
        assert!(matches!(
            ipam.release("nope"),
            Err(IpamError::NotAllocated(_))
        ));
    }

    #[test]
    fn double_release_returns_not_allocated() {
        let ipam = Ipam::default();
        let _ = ipam.allocate("a1").unwrap();
        let _ = ipam.release("a1").unwrap();
        assert!(matches!(ipam.release("a1"), Err(IpamError::NotAllocated(_))));
        let inner = ipam.inner.lock().unwrap();
        assert_eq!(inner.released.len(), 1);
    }

    #[test]
    fn delegated_prefix_for_nested_auraed() {
        // Configure a /80 device prefix carved from a /64 pool: each
        // delegation gives the guest 2^48 addresses.
        let v6: Ipv6Net = "fd00:ae::/64".parse().unwrap();
        let cfg = IpamConfig::new(v6, /* dev v6 */ 80).unwrap();
        let ipam = Ipam::new(cfg);

        let alloc = ipam.allocate("nested").unwrap();
        assert_eq!(alloc.delegated.prefix_len(), 80);
        // Block 1 of /80 inside fd00:ae::/64 starts at
        // fd00:ae:0:0:0001:: — the next /80 boundary after the base.
        assert_eq!(
            alloc.delegated.network(),
            Ipv6Addr::new(0xfd00, 0x00ae, 0, 0, 0x0001, 0, 0, 0)
        );
    }

    #[test]
    fn pool_exhausted_for_tiny_pool() {
        // /126 has 4 addresses: ::0, ::1 (host), ::2 (a1), ::3 (a2).
        // The third allocate must fail since no addresses remain.
        let v6: Ipv6Net = "fd00:abcd::/126".parse().unwrap();
        let cfg = IpamConfig::new(v6, 128).unwrap();
        let ipam = Ipam::new(cfg);
        let _ = ipam.allocate("a1").unwrap();
        let _ = ipam.allocate("a2").unwrap();
        assert!(matches!(ipam.allocate("a3"), Err(IpamError::PoolExhausted)));
    }

    #[test]
    fn allocate_after_release_drains_stack() {
        let ipam = Ipam::default();
        let alloc1 = ipam.allocate("a1").unwrap();
        let _ = ipam.allocate("a2").unwrap();
        let _ = ipam.release("a1").unwrap();

        let reused = ipam.allocate("a3").unwrap();
        assert_eq!(reused.guest_ip, alloc1.guest_ip);

        // After consuming reuse, a4 advances from next_block (which is
        // already at 4 because a1 took 2 and a2 took 3).
        let fresh = ipam.allocate("a4").unwrap();
        assert_eq!(
            fresh.guest_ip,
            Ipv6Addr::new(0xfd00, 0x00ae, 0, 0, 0, 0, 0, 4)
        );
    }

    #[test]
    fn delegated_pool_contains_guest_ip() {
        // ipnet's `contains` works for both addresses and networks; verify
        // the guest_ip is always inside the delegated prefix.
        let ipam = Ipam::default();
        let alloc = ipam.allocate("a1").unwrap();
        assert!(alloc.delegated.contains(&alloc.guest_ip));
    }
}
