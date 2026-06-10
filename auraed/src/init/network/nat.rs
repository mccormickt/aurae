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

//! IPv6 NAT setup for cell internet egress.
//!
//! Owns a dedicated `inet aurae` nft table containing two chains:
//!   * `forward_accept` (filter, hook=forward, prio=-5) — anti-spoof drops
//!     first, then egress + return rules. The negative priority puts our
//!     chain ahead of the conventional inet filter priority 0, so on plain
//!     hosts our `accept` short-circuits later filters.
//!     Operator-hostile firewalls (firewalld zones, ufw deny-by-default)
//!     still require a manual allow rule.
//!   * `nat_postrouting` (nat, hook=postrouting, prio=NF_IP_PRI_NAT_SRC) —
//!     `masquerade` for the cell pool on the WAN egress interface.
//!
//! The ruleset is built as a typed JSON document and applied by shelling
//! out to the `nft` binary (via the `nftables` crate). `nft` must be on
//! the host's `$PATH` at runtime. Owns nothing else on the host: the
//! table is torn down by deleting it.

use ipnet::Ipv6Net;
use nftables::{
    batch::Batch,
    expr::{
        CT, Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField,
        Prefix, SetItem,
    },
    helper::{NftablesError, apply_ruleset},
    schema::{Chain, NfListObject, Rule, Table},
    stmt::{Match, Operator, Statement},
    types::{NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;
use std::io;
use std::sync::Mutex;
use tracing::warn;

const TABLE_NAME: &str = "aurae";
const FORWARD_CHAIN: &str = "forward_accept";
const POSTROUTING_CHAIN: &str = "nat_postrouting";

/// Priority for our forward chain. -5 sits before the conventional inet
/// filter priority 0, so on plain hosts our `accept` short-circuits the rest
/// of the filter pipeline.
const FORWARD_PRIORITY: i32 = -5;

/// `NF_IP_PRI_NAT_SRC` from `<linux/netfilter_ipv4.h>`.
const POSTROUTING_PRIORITY: i32 = 100;

const FAMILY: NfFamily = NfFamily::INet;

/// Configuration the NAT ruleset depends on: the cell pool and the WAN
/// egress interface. Used internally by [`NatManager`] to build the
/// install batch and the delete batch.
struct NatState {
    pool_v6: Ipv6Net,
    wan_iface: String,
}

impl NatState {
    fn new(pool_v6: Ipv6Net, wan_iface: &str) -> io::Result<Self> {
        if wan_iface.is_empty() || wan_iface.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wan_iface is empty or contains a NUL byte",
            ));
        }
        Ok(Self { pool_v6, wan_iface: wan_iface.to_string() })
    }

    fn build_install(&self) -> Batch<'_> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Table(self.table()));
        batch.add(NfListObject::Chain(self.forward_chain()));
        batch.add(NfListObject::Chain(self.postrouting_chain()));
        batch.add(NfListObject::Rule(self.rule_antispoof()));
        batch.add(NfListObject::Rule(self.rule_allow_egress()));
        batch.add(NfListObject::Rule(self.rule_allow_return()));
        batch.add(NfListObject::Rule(self.rule_masquerade()));
        batch
    }

    /// The delete batch is `add table` + `delete table`, applied in one
    /// nft transaction: `add` is a no-op when the table already exists
    /// and creates it when it doesn't, so the `delete` target is
    /// guaranteed to exist and the batch never fails with "no such
    /// table". Detecting that error after the fact doesn't work — the
    /// `nftables` crate spawns `nft` with stderr inherited (not piped),
    /// so `NftablesError::NftFailed.stderr` is always empty and the
    /// message text is unavailable for matching.
    fn build_delete(&self) -> Batch<'_> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Table(self.table()));
        batch.delete(NfListObject::Table(self.table()));
        batch
    }

    fn table(&self) -> Table<'_> {
        Table { family: FAMILY, name: TABLE_NAME.into(), handle: None }
    }

    fn forward_chain(&self) -> Chain<'_> {
        Chain {
            family: FAMILY,
            table: TABLE_NAME.into(),
            name: FORWARD_CHAIN.into(),
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Forward),
            prio: Some(FORWARD_PRIORITY),
            ..Chain::default()
        }
    }

    fn postrouting_chain(&self) -> Chain<'_> {
        Chain {
            family: FAMILY,
            table: TABLE_NAME.into(),
            name: POSTROUTING_CHAIN.into(),
            _type: Some(NfChainType::NAT),
            hook: Some(NfHook::Postrouting),
            prio: Some(POSTROUTING_PRIORITY),
            ..Chain::default()
        }
    }

    /// Build a rule attached to `chain` carrying the given statements.
    fn rule<'a>(
        &self,
        chain: &'static str,
        statements: Vec<Statement<'a>>,
    ) -> Rule<'a> {
        Rule {
            family: FAMILY,
            table: TABLE_NAME.into(),
            chain: chain.into(),
            expr: Cow::Owned(statements),
            ..Rule::default()
        }
    }

    /// Anti-spoof: drop any cell-side packet (iifname != wan) whose saddr
    /// is outside the configured pool. Constraining to non-WAN iifname
    /// keeps WAN return traffic (saddr=external endpoint) from being
    /// matched here — without it, established/related return flows
    /// would die before the conntrack-accept rule runs.
    ///
    /// Note: this rule does NOT enforce per-iif saddr binding — that is
    /// the cell-net BPF guard's job (see `init/network/bpf.rs`), which
    /// pins each cell's source addresses to its delegated prefix at tc
    /// ingress on the netkit primary. This pool-granularity rule stays
    /// as defense in depth for guard-less (degraded) operation.
    ///
    /// Also note: cell→cell traffic delivered via the guard's
    /// `bpf_redirect_peer` fast path never traverses this chain (BPF
    /// redirect bypasses netfilter); only gateway-local and WAN-bound
    /// traffic shows up here.
    fn rule_antispoof(&self) -> Rule<'_> {
        self.rule(
            FORWARD_CHAIN,
            vec![
                match_meta(MetaKey::Iifname, &self.wan_iface, Operator::NEQ),
                match_addr("saddr", self.pool_v6, Operator::NEQ),
                Statement::Drop(None),
            ],
        )
    }

    /// Forward: accept egress (cell pool → wan).
    fn rule_allow_egress(&self) -> Rule<'_> {
        self.rule(
            FORWARD_CHAIN,
            vec![
                match_addr("saddr", self.pool_v6, Operator::EQ),
                match_meta(MetaKey::Oifname, &self.wan_iface, Operator::EQ),
                Statement::Accept(None),
            ],
        )
    }

    /// Forward: accept return traffic (wan → cell pool) when conntrack
    /// says it's part of an established / related flow.
    fn rule_allow_return(&self) -> Rule<'_> {
        self.rule(
            FORWARD_CHAIN,
            vec![
                match_addr("daddr", self.pool_v6, Operator::EQ),
                match_meta(MetaKey::Iifname, &self.wan_iface, Operator::EQ),
                match_ct_state_established_or_related(),
                Statement::Accept(None),
            ],
        )
    }

    /// Postrouting: masquerade the pool out the WAN interface.
    fn rule_masquerade(&self) -> Rule<'_> {
        self.rule(
            POSTROUTING_CHAIN,
            vec![
                match_addr("saddr", self.pool_v6, Operator::EQ),
                match_meta(MetaKey::Oifname, &self.wan_iface, Operator::EQ),
                Statement::Masquerade(None),
            ],
        )
    }
}

fn match_meta<'a>(key: MetaKey, value: &'a str, op: Operator) -> Statement<'a> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta { key })),
        right: Expression::String(Cow::Borrowed(value)),
        op,
    })
}

/// Match `ip6 <field>` against the configured pool, with the given
/// operator. `field` is `"saddr"` or `"daddr"`.
fn match_addr<'a>(
    field: &'static str,
    pool: Ipv6Net,
    op: Operator,
) -> Statement<'a> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(
            Payload::PayloadField(PayloadField {
                protocol: "ip6".into(),
                field: field.into(),
            }),
        )),
        right: Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(Expression::String(
                pool.network().to_string().into(),
            )),
            len: pool.prefix_len() as u32,
        })),
        op,
    })
}

/// Match `ct state {established, related}`.
fn match_ct_state_established_or_related<'a>() -> Statement<'a> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::CT(CT {
            key: "state".into(),
            family: None,
            dir: None,
        })),
        right: Expression::Named(NamedExpression::Set(vec![
            SetItem::Element(Expression::String("established".into())),
            SetItem::Element(Expression::String("related".into())),
        ])),
        op: Operator::IN,
    })
}

/// Manages the lifecycle of IPv6 NAT nftables rules for cell internet
/// egress. Construct via [`NatManager::new`]; the manager starts
/// uninstalled and tracks its own configured state.
///
/// [`Self::install`] is idempotent and reconfigure-safe: it deletes any
/// existing `inet aurae` table before installing the new one, so calling
/// it again with different params transparently swaps the ruleset.
/// [`Self::uninstall`] is a no-op when nothing is installed. The internal
/// `Mutex` serializes installs/uninstalls; reads (`is_installed`) take
/// the lock briefly.
///
/// Requires the `nft` binary on the host's `$PATH` at runtime.
pub(crate) struct NatManager {
    state: Mutex<Option<NatState>>,
}

impl NatManager {
    pub(crate) fn new() -> Self {
        Self { state: Mutex::new(None) }
    }

    /// Install (or re-install) the NAT ruleset. Always deletes any
    /// pre-existing `inet aurae` table first, so this works for fresh
    /// installs, leftover-from-previous-daemon recovery, and runtime
    /// reconfigure.
    pub(crate) fn install(
        &self,
        pool_v6: Ipv6Net,
        wan_iface: &str,
    ) -> io::Result<()> {
        let new_state = NatState::new(pool_v6, wan_iface)?;
        let mut guard = self.state.lock().expect("nat mutex poisoned");

        // Clear any pre-existing `inet aurae` table. The delete batch is
        // idempotent (add-before-delete), so this succeeds whether or
        // not the table exists — a failure here is a real nft problem.
        if let Err(e) = apply_batch(new_state.build_delete()) {
            return Err(io_err("delete prior nft table", e));
        }

        if let Err(e) = apply_batch(new_state.build_install()) {
            // Best-effort cleanup of any partial install; kernel and
            // tracked state both end up empty, so a retry is well-defined.
            if let Err(cleanup_err) = apply_batch(new_state.build_delete()) {
                warn!(
                    "NAT install failed and cleanup also failed: \
                     install={e}, cleanup={cleanup_err}. Operator may \
                     need to `nft delete table inet aurae`."
                );
            }
            *guard = None;
            return Err(io_err("install nft ruleset", e));
        }

        *guard = Some(new_state);
        Ok(())
    }

    /// Tear down the NAT ruleset. No-op when nothing is installed, and
    /// safe when the operator already removed the table (the delete
    /// batch is idempotent via add-before-delete).
    pub(crate) fn uninstall(&self) -> io::Result<()> {
        let mut guard = self.state.lock().expect("nat mutex poisoned");
        let Some(state) = guard.take() else { return Ok(()) };
        apply_batch(state.build_delete())
            .map_err(|e| io_err("uninstall nft ruleset", e))
    }

    pub(crate) fn is_installed(&self) -> bool {
        self.state.lock().map(|g| g.is_some()).unwrap_or(false)
    }
}

impl Default for NatManager {
    fn default() -> Self {
        Self::new()
    }
}

fn apply_batch(batch: Batch<'_>) -> Result<(), NftablesError> {
    apply_ruleset(&batch.to_nftables())
}

fn io_err(hint: &str, err: NftablesError) -> io::Error {
    io::Error::other(format!("nft {hint}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nftables::schema::{NfCmd, NfObject};

    fn test_pool_v6() -> Ipv6Net {
        "fd00:ae::/64".parse().expect("valid test v6 pool")
    }

    const TEST_IFACE: &str = "eth0";

    fn test_state() -> NatState {
        NatState::new(test_pool_v6(), TEST_IFACE).expect("valid test iface")
    }

    // ---- NatManager lifecycle ----

    #[test]
    fn manager_starts_uninstalled() {
        let m = NatManager::new();
        assert!(!m.is_installed());
    }

    #[test]
    fn uninstall_on_uninstalled_manager_is_noop() {
        let m = NatManager::new();
        m.uninstall().expect("uninstall on empty manager is ok");
        assert!(!m.is_installed());
    }

    // ---- NatState construction ----

    #[test]
    fn state_rejects_nul_byte_iface() {
        assert!(NatState::new(test_pool_v6(), "eth0\0bad").is_err());
    }

    #[test]
    fn state_rejects_empty_iface() {
        assert!(NatState::new(test_pool_v6(), "").is_err());
    }

    // ---- Batch shape ----
    //
    // Helpers that extract typed objects from a batch so tests can assert
    // against the structured Nftables model rather than serialized JSON.

    fn expect_add<'a, 'b>(obj: &'b NfObject<'a>) -> &'b NfListObject<'a> {
        match obj {
            NfObject::CmdObject(NfCmd::Add(inner)) => inner,
            other => panic!("expected Add(_), got {other:?}"),
        }
    }

    fn expect_delete<'a, 'b>(obj: &'b NfObject<'a>) -> &'b NfListObject<'a> {
        match obj {
            NfObject::CmdObject(NfCmd::Delete(inner)) => inner,
            other => panic!("expected Delete(_), got {other:?}"),
        }
    }

    fn expect_table<'a, 'b>(obj: &'b NfListObject<'a>) -> &'b Table<'a> {
        match obj {
            NfListObject::Table(t) => t,
            other => panic!("expected Table, got {other:?}"),
        }
    }

    fn expect_chain<'a, 'b>(obj: &'b NfListObject<'a>) -> &'b Chain<'a> {
        match obj {
            NfListObject::Chain(c) => c,
            other => panic!("expected Chain, got {other:?}"),
        }
    }

    fn expect_rule<'a, 'b>(obj: &'b NfListObject<'a>) -> &'b Rule<'a> {
        match obj {
            NfListObject::Rule(r) => r,
            other => panic!("expected Rule, got {other:?}"),
        }
    }

    #[test]
    fn install_batch_has_table_two_chains_four_rules() {
        let state = test_state();
        let nft = state.build_install().to_nftables();
        let objs = &*nft.objects;
        assert_eq!(objs.len(), 7, "1 table + 2 chains + 4 rules");

        // Index 0: the table.
        let table = expect_table(expect_add(&objs[0]));
        assert_eq!(table.family, FAMILY);
        assert_eq!(table.name, TABLE_NAME);

        // Indices 1, 2: forward and postrouting chains.
        let forward = expect_chain(expect_add(&objs[1]));
        assert_eq!(forward.name, FORWARD_CHAIN);
        assert_eq!(forward._type, Some(NfChainType::Filter));
        assert_eq!(forward.hook, Some(NfHook::Forward));
        assert_eq!(forward.prio, Some(FORWARD_PRIORITY));

        let postrouting = expect_chain(expect_add(&objs[2]));
        assert_eq!(postrouting.name, POSTROUTING_CHAIN);
        assert_eq!(postrouting._type, Some(NfChainType::NAT));
        assert_eq!(postrouting.hook, Some(NfHook::Postrouting));
        assert_eq!(postrouting.prio, Some(POSTROUTING_PRIORITY));

        // Indices 3..7: the four rules, all under inet aurae.
        for obj in &objs[3..7] {
            let rule = expect_rule(expect_add(obj));
            assert_eq!(rule.family, FAMILY);
            assert_eq!(rule.table, TABLE_NAME);
        }
    }

    #[test]
    fn antispoof_rule_drops_offpool_traffic_from_non_wan() {
        let state = test_state();
        let nft = state.build_install().to_nftables();
        let rule = expect_rule(expect_add(&nft.objects[3]));
        assert_eq!(rule.chain, FORWARD_CHAIN);
        assert_eq!(rule.expr.len(), 3);
        assert_match_meta(
            &rule.expr[0],
            MetaKey::Iifname,
            "eth0",
            Operator::NEQ,
        );
        assert_match_addr(&rule.expr[1], "saddr", Operator::NEQ);
        assert!(matches!(rule.expr[2], Statement::Drop(None)));
    }

    #[test]
    fn allow_egress_rule_accepts_pool_out_wan() {
        let state = test_state();
        let nft = state.build_install().to_nftables();
        let rule = expect_rule(expect_add(&nft.objects[4]));
        assert_eq!(rule.chain, FORWARD_CHAIN);
        assert_eq!(rule.expr.len(), 3);
        assert_match_addr(&rule.expr[0], "saddr", Operator::EQ);
        assert_match_meta(
            &rule.expr[1],
            MetaKey::Oifname,
            "eth0",
            Operator::EQ,
        );
        assert!(matches!(rule.expr[2], Statement::Accept(None)));
    }

    #[test]
    fn allow_return_rule_accepts_established_related_from_wan() {
        let state = test_state();
        let nft = state.build_install().to_nftables();
        let rule = expect_rule(expect_add(&nft.objects[5]));
        assert_eq!(rule.chain, FORWARD_CHAIN);
        assert_eq!(rule.expr.len(), 4);
        assert_match_addr(&rule.expr[0], "daddr", Operator::EQ);
        assert_match_meta(
            &rule.expr[1],
            MetaKey::Iifname,
            "eth0",
            Operator::EQ,
        );
        assert_match_ct_state_established_related(&rule.expr[2]);
        assert!(matches!(rule.expr[3], Statement::Accept(None)));
    }

    #[test]
    fn masquerade_rule_masqs_pool_out_wan() {
        let state = test_state();
        let nft = state.build_install().to_nftables();
        let rule = expect_rule(expect_add(&nft.objects[6]));
        assert_eq!(rule.chain, POSTROUTING_CHAIN);
        assert_eq!(rule.expr.len(), 3);
        assert_match_addr(&rule.expr[0], "saddr", Operator::EQ);
        assert_match_meta(
            &rule.expr[1],
            MetaKey::Oifname,
            "eth0",
            Operator::EQ,
        );
        assert!(matches!(rule.expr[2], Statement::Masquerade(None)));
    }

    #[test]
    fn delete_batch_adds_then_deletes_the_table() {
        let state = test_state();
        let nft = state.build_delete().to_nftables();
        let objs = &*nft.objects;
        assert_eq!(
            objs.len(),
            2,
            "delete batch is Add(Table) then Delete(Table) so the delete \
             can never fail on a missing table"
        );
        let added = expect_table(expect_add(&objs[0]));
        assert_eq!(added.family, FAMILY);
        assert_eq!(added.name, TABLE_NAME);
        let deleted = expect_table(expect_delete(&objs[1]));
        assert_eq!(deleted.family, FAMILY);
        assert_eq!(deleted.name, TABLE_NAME);
    }

    // ---- Statement structural assertions ----

    fn assert_match_meta(
        stmt: &Statement<'_>,
        expected_key: MetaKey,
        expected_iface: &str,
        expected_op: Operator,
    ) {
        let Statement::Match(m) = stmt else {
            panic!("expected Match statement, got {stmt:?}");
        };
        assert_eq!(m.op, expected_op);
        match &m.left {
            Expression::Named(NamedExpression::Meta(meta)) => {
                assert_eq!(meta.key, expected_key);
            }
            other => panic!("expected Meta lhs, got {other:?}"),
        }
        match &m.right {
            Expression::String(s) => assert_eq!(s.as_ref(), expected_iface),
            other => panic!("expected string rhs, got {other:?}"),
        }
    }

    fn assert_match_addr(
        stmt: &Statement<'_>,
        expected_field: &str,
        expected_op: Operator,
    ) {
        let Statement::Match(m) = stmt else {
            panic!("expected Match statement, got {stmt:?}");
        };
        assert_eq!(m.op, expected_op);
        match &m.left {
            Expression::Named(NamedExpression::Payload(
                Payload::PayloadField(PayloadField { protocol, field }),
            )) => {
                assert_eq!(protocol.as_ref(), "ip6");
                assert_eq!(field.as_ref(), expected_field);
            }
            other => panic!("expected ip6 payload lhs, got {other:?}"),
        }
        match &m.right {
            Expression::Named(NamedExpression::Prefix(prefix)) => {
                let Expression::String(addr) = &*prefix.addr else {
                    panic!(
                        "expected prefix addr to be String, got {:?}",
                        prefix.addr
                    );
                };
                assert_eq!(addr.as_ref(), "fd00:ae::");
                assert_eq!(prefix.len, 64);
            }
            other => panic!("expected Prefix rhs, got {other:?}"),
        }
    }

    fn assert_match_ct_state_established_related(stmt: &Statement<'_>) {
        let Statement::Match(m) = stmt else {
            panic!("expected Match statement, got {stmt:?}");
        };
        assert_eq!(m.op, Operator::IN);
        match &m.left {
            Expression::Named(NamedExpression::CT(ct)) => {
                assert_eq!(ct.key.as_ref(), "state");
            }
            other => panic!("expected CT lhs, got {other:?}"),
        }
        let Expression::Named(NamedExpression::Set(items)) = &m.right else {
            panic!("expected anonymous set rhs, got {:?}", m.right);
        };
        let strings: Vec<&str> = items
            .iter()
            .map(|item| match item {
                SetItem::Element(Expression::String(s)) => s.as_ref(),
                other => panic!("expected string set item, got {other:?}"),
            })
            .collect();
        assert_eq!(strings, ["established", "related"]);
    }
}
