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
//! The allocator gives out and releases IPv6 prefix delegations for opaque
//! string identifiers. All allocations share the host gateway at
//! `pool_base + 1`. The same `/128` host address on more than one endpoint
//! is correct, because each endpoint has its own L3 link and there is no
//! common L2 segment. Thus there is no neighbour discovery conflict.
//!
//! The allocator divides the pool into blocks with the size
//! `device_prefix`. It calculates the address of a block and does not walk
//! the pool. To allocate, it takes the next block that does not contain the
//! host slot. To release, it pushes the block onto a reuse stack.
//!
//! A construction error uses the [`ValidationError`] type. A runtime error
//! of the allocator uses [`IpamError`].

use ipnet::Ipv6Net;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use thiserror::Error;
use validation::ValidationError;

/// The default ULA pool fd00:ae::/64. The digits "ae" are for aurae.
pub const DEFAULT_POOL_V6: &str = "fd00:ae::/64";

/// The default device prefix /128 gives one address to each device.
pub const DEFAULT_DEVICE_PREFIX_V6: u8 = 128;

/// The IPAM key of a VM allocation. Cells and VMs use the same pool. The
/// prefix `cell:` or `vm:` keeps the two key spaces separate. A cell uses
/// the key `cell:<name>`.
pub fn vm_key(vm_id: impl std::fmt::Display) -> String {
    format!("vm:{vm_id}")
}

/// The runtime errors of the IPAM allocator. A construction error, for
/// example a parse error or an invalid prefix range, uses
/// [`ValidationError`].
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

/// The configuration of the IPAM. [`IpamConfig::new`] and
/// [`IpamConfig::default`] build it. Both enforce
/// `pool_prefix <= device_prefix`.
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

/// The IPv6 allocation of one cell. `host_ip` is the common gateway on the
/// endpoint side. `delegated` is the prefix of the guest device. `guest_ip`
/// is the first usable address in `delegated`, and the guest binds it.
#[derive(Debug, Clone)]
pub struct Allocation {
    pub(crate) host_ip: Ipv6Addr,
    pub(crate) delegated: Ipv6Net,
    pub(crate) guest_ip: Ipv6Addr,
}

/// IP Address Manager.
///
/// It divides the pool into blocks with the size `device_prefix` and gives
/// them out in sequence. It does not give out a block that contains the
/// common host slot at `pool_base + 1`.
///
/// The type contains a [`std::sync::Mutex`]. Thus a caller can share an
/// `Ipam` without an external lock. Each critical section is short and
/// contains no `await`, therefore a synchronous mutex is correct.
#[derive(Debug)]
pub struct Ipam {
    inner: std::sync::Mutex<IpamInner>,
}

/// The state of the allocator. It is a separate struct. one `Mutex`
/// in `Ipam` protects all fields and no field is public.
#[derive(Debug)]
struct IpamInner {
    config: IpamConfig,
    /// The block index of the next allocation.
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

    /// The configured pool. `Network::init_host_network` reads it.
    /// the nft ruleset uses the same prefix as the allocator.
    pub fn pool(&self) -> Ipv6Net {
        self.inner.lock().expect("ipam mutex poisoned").config.pool_v6
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
        // Find the first guest block. It is the lowest block without the
        // common host slot at `pool_base + 1`. A `device_prefix` of 128
        // gives blocks with one address. Block 0 is then `pool_base` and
        // block 1 is the host. The guests start at block 2. A
        // `device_prefix` below 128 puts the host slot in block 0. the
        // guests start at block 1.
        let next_block = if config.device_prefix_v6 == 128 { 2 } else { 1 };
        Self {
            config,
            next_block,
            allocated: HashMap::new(),
            released: Vec::new(),
        }
    }

    /// The common v6 host gateway of each endpoint at `pool_base + 1`.
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

/// Calculate the block `n` of `pool` with the size `device_prefix`:
/// `pool_base + n * 2^(128 - device_prefix)`. The function checks the
/// result against the pool. It calculates the address, because
/// `ipnet::Ipv6Subnets` implements `next` only. `Iterator::nth(n)` is O(n).
/// Each allocation would otherwise walk the pool from its start.
///
/// The function returns `None` if the block is outside the pool. The
/// configuration enforces `pool_prefix <= device_prefix`. This is the
/// only failure.
fn nth_subnet(pool: &Ipv6Net, device_prefix: u8, n: u128) -> Option<Ipv6Net> {
    let block_bits = 128u32.checked_sub(u32::from(device_prefix))?;
    // Calculate the number of blocks in the pool. `pool_prefix` is less
    // than or equal to `device_prefix`. The shift is in range. A value
    // of 128 gives the full address space.
    let pool_bits = 128u32 - u32::from(pool.prefix_len());
    let block_count = match pool_bits.checked_sub(block_bits)? {
        128 => u128::MAX,
        bits => 1u128 << bits,
    };
    if n >= block_count {
        return None;
    }

    let base = u128::from(pool.network());
    let offset = n.checked_mul(1u128 << block_bits)?;
    let addr = Ipv6Addr::from(base.checked_add(offset)?);
    Ipv6Net::new(addr, device_prefix).ok()
}

/// Calculate the index of `block` in `pool`. This is the inverse of
/// [`nth_subnet`]. The release path pushes this index onto the reuse stack.
/// Both parameters come from the allocator. `block` is always aligned
/// to `device_prefix` in `pool`.
fn block_index(pool: &Ipv6Net, block: &Ipv6Net) -> u128 {
    let offset =
        u128::from(block.network()).saturating_sub(u128::from(pool.network()));
    match 128u32.checked_sub(u32::from(block.prefix_len())) {
        Some(0) | None => offset,
        Some(block_bits) => offset >> block_bits,
    }
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

        // The first guest is fd00:ae::2. The host gateway fd00:ae::1 is
        // the same on each endpoint.
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
        // Use a /80 device prefix in a /64 pool. Each delegation gives the
        // guest 2^48 addresses.
        let v6: Ipv6Net = "fd00:ae::/64".parse().unwrap();
        let cfg = IpamConfig::new(v6, /* dev v6 */ 80).unwrap();
        let ipam = Ipam::new(cfg);

        let alloc = ipam.allocate("nested").unwrap();
        assert_eq!(alloc.delegated.prefix_len(), 80);
        // Block 1 of the /80 blocks in fd00:ae::/64 starts at
        // fd00:ae:0:0:0001::, the first /80 boundary after the base.
        assert_eq!(
            alloc.delegated.network(),
            Ipv6Addr::new(0xfd00, 0x00ae, 0, 0, 0x0001, 0, 0, 0)
        );
    }

    #[test]
    fn pool_exhausted_for_tiny_pool() {
        // A /126 has the four addresses ::0, ::1 for the host, ::2 for a1,
        // and ::3 for a2. The third allocation must fail.
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

        // The reuse stack is now empty. a4 comes from `next_block`.
        // That index is 4, because a1 took 2 and a2 took 3.
        let fresh = ipam.allocate("a4").unwrap();
        assert_eq!(
            fresh.guest_ip,
            Ipv6Addr::new(0xfd00, 0x00ae, 0, 0, 0, 0, 0, 4)
        );
    }

    /// `nth_subnet` calculates the block. Compare the result with the
    /// `subnets()` iterator, so that the arithmetic stays correct.
    #[test]
    fn nth_subnet_matches_the_subnets_iterator() {
        for (pool, dev) in
            [("fd00:ae::/64", 128u8), ("fd00:ae::/64", 80), ("fd00::/8", 16)]
        {
            let pool: Ipv6Net = pool.parse().expect("valid pool");
            let mut iter = pool.subnets(dev).expect("subnets");
            for n in 0..8u128 {
                assert_eq!(
                    nth_subnet(&pool, dev, n),
                    iter.next(),
                    "block {n} of {pool} at /{dev}"
                );
            }
        }
    }

    #[test]
    fn nth_subnet_rejects_blocks_past_the_end_of_the_pool() {
        // A /126 with a /128 device prefix has four blocks.
        let pool: Ipv6Net = "fd00:abcd::/126".parse().expect("valid pool");
        assert!(nth_subnet(&pool, 128, 3).is_some());
        assert!(nth_subnet(&pool, 128, 4).is_none());
        assert!(nth_subnet(&pool, 128, u128::MAX).is_none());
    }

    #[test]
    fn block_index_inverts_nth_subnet() {
        let pool: Ipv6Net = "fd00:ae::/64".parse().expect("valid pool");
        for dev in [128u8, 96, 80] {
            for n in 0..8u128 {
                let block = nth_subnet(&pool, dev, n).expect("block exists");
                assert_eq!(block_index(&pool, &block), n, "/{dev} block {n}");
            }
        }
    }

    #[test]
    fn delegated_pool_contains_guest_ip() {
        // The `contains` function of ipnet accepts an address and a
        // network. The guest_ip must always be in the delegated prefix.
        let ipam = Ipam::default();
        let alloc = ipam.allocate("a1").unwrap();
        assert!(alloc.delegated.contains(&alloc.guest_ip));
    }
}
