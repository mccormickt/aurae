# AF_XDP VM networking

The optional `auraed/af-xdp` feature connects a VM to Aurae's routed IPv6
network with an external Cloud Hypervisor AF_XDP endpoint. Legacy `Allocate`
still selects TAP. Request `AllocateWithNetwork` with backend `AF_XDP` and a
logical NIC ID to select this adapter. There is no TAP fallback. A daemon
built without this feature returns `Unimplemented` for explicit AF_XDP.

## Build and guest configuration

The dependency pins are Cloud Hypervisor `adb285f2e0c84eacd5cb952ae4de16911ddaad0a`
and its Aya AF_XDP dependency `f0471a9bec8d297d6962e8f604dbaf21d4036701`.
The feature build requires `nightly-2026-09-25`, `rust-src`, and `bpf-linker`
0.11.1. Building that linker from source requires LLVM 23 development libraries.
The default TAP build still uses the repository's stable Rust toolchain.

From the repository root:

```bash
rustup toolchain install nightly-2026-09-25 --component rust-src
LLVM_PREFIX=/usr/lib/llvm-23 cargo +nightly-2026-09-25 install bpf-linker --version 0.11.1 --locked
buf generate api
cargo +nightly-2026-09-25 build --locked -p auraed --features af-xdp
cargo +nightly-2026-09-25 build --manifest-path ebpf/Cargo.toml --locked \
  --bin guard-xdp-vm-net --target bpfel-unknown-none -Z build-std=core --release
```

Install `ebpf/target/bpfel-unknown-none/release/guard-xdp-vm-net` under
`<auraed library_dir>/ebpf/`, alongside the other Aurae BPF objects. Both the
host daemon and nested cell daemon must use the feature-enabled binary.
Install `ethtool` in the daemon's executable search path, including nested
cells. Setup fails if it cannot disable the VM primary's offloads.
Setup needs network administration, BPF and raw-socket privileges, and enough
locked memory for CH's approximately 16 MiB UMEM per endpoint. It must fail if
the kernel cannot supply generic XDP FD links or explicit COPY sockets.

Use an Aurae pid1 guest with support for `aurae.gw_mac`. Aurae supplies the
delegated IPv6 prefix, gateway address, and `aurae.gw_mac=00:00:00:00:00:00` on
the kernel command line. Guest init installs a permanent gateway neighbor.
A different guest init must implement the same address, route, and neighbor
configuration. Neighbor discovery is not provided by the MAC-less transport.

VM drives use raw images, as produced by the repository's `prepare-image`
target. Aurae supplies CH's required explicit `Raw` image type for both TAP
and AF_XDP VMs. Convert other disk formats to raw before allocation.

## Packet path and policy

Each VM gets its own paired L3 netkit endpoint inside the hosting daemon's
network namespace. Its primary replaces the routed TAP; its unaddressed peer
is the socket interface. The cell's shared uplink and control address remain
unchanged. Each peer binds queue 0 with explicit COPY; its XSKMAP key is 17.
The key, queue, and logical NIC ID are independent. Independent UMEM pools
cannot share one device/queue.

Before bringing up the pair, Aurae disables TX checksum, scatter-gather,
TSO and GSO offloads on the owned primary with `ethtool`. The kernel must
complete checksums and segmentation before packets reach the peer's XSK.
Generic XSK delivery does not preserve skb offload metadata, and CH supplies
no guest checksum or segmentation offloads. Shared cell links are unchanged.

VM TX enters its primary, where an XDP source guard accepts only IPv6 sources
inside that VM's delegated prefix. The packet then enters ordinary routing
and nftables. Aurae binds the primary to the same per-endpoint nft source
policy used for TAP. No BPF program redirects to another interface. Host and
sibling-cell restrictions remain under the outer daemon's nftables policy.
Within a cell, the namespace's existing forwarding policy still applies.

Return traffic passes routing and any FORWARD rules before transmission on
the primary reaches the peer's generic XDP hook. That hook accepts only the
VM's delegated destination, rejects invalid/local and reflected VM sources,
and supplies the configured guest destination MAC and zero gateway source
MAC. It then redirects to the prepared socket. It does not intercept the
shared cell uplink or bypass an intended local INPUT path. CH preserves these
Ethernet bytes; it performs no Aurae-specific MAC rewriting.

## Resource lifetime

Setup and cleanup execute on Aurae's dedicated lifecycle OS thread while it
holds the owned VM-cache lock. RPC cancellation cannot interrupt them. No
namespace or capability change runs on a Tokio worker. CH restricts its own
VMM thread and owns packet workers, sockets and UMEM. Aurae owns both netkit
links, source bindings, XDP links/maps and address leases.
VM creation errors stop and join the VMM thread before allocation rollback.
CH requires Landlock ABI V3; the host kernel must enable it.

Before Stop or Free, Aurae puts the pair down, then drops its FD-owned steering
links and map references. Stop waits for CH shutdown and the release fence;
the down pair and address remain available for Start. Start prepares a fresh
socket. A preparation failure, including deferred-kernel `EBUSY`, retains the
down endpoint and allocation for retry or Free. A boot error has a potentially
unknown outcome: Aurae revokes steering, signals VMM exit, joins the thread,
waits for the fence, and only then deletes the pair and releases the address.
Cleanup failure retains state for a later Free. Interface cleanup checks a
random nonzero ownership group assigned to both endpoints during creation.
It does not remove shared cell resources.

Guest-requested reset shuts down an AF_XDP VM; automatic reboot does not
silently reconstruct privileged resources. Hotplug and migration are not
supported by this adapter. Daemon-crash recovery of VM leases is not provided.

## Kernel limitation

This is an experimental adapter, not a claim of stock-kernel transport support.
The disposable Zeus fixture uses a local netkit repair which runs
`eth_type_trans`, resets the network header, and restores Ethernet before BPF.
Unrepaired COPY TX can complete while delivering no IPv6 payload. The guest's
zero destination MAC must match the receiving L3 netkit device address;
foreign nonzero destinations must remain rejected, not forced to `PACKET_HOST`.
The adapter does not detect or install this kernel repair. Attach, bind, boot
and TX completion alone are not evidence of bidirectional delivery.

Source/protocol handling beyond the tested fixture and offload coverage remain
kernel validation obligations. No throughput improvement is claimed. Before
deployment, verify actual Aurae guest payloads in both directions, source
spoof rejection, multiple VMs, selective delivery, ordinary cell traffic,
restart, and owned teardown on the exact kernel and guest images in use.
