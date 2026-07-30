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

//! nftables rules for cell networking.
//!
//! The `source_filter` chain runs at prerouting. It drops non-IPv6 cell
//! traffic. It also drops an IPv6 source that is not assigned to the cell.
//! Prerouting covers local and forwarded traffic.
//!
//! The `forward_accept` chain permits cell forwarding. The
//! `nat_postrouting` chain provides egress when the host has a WAN route.
//!
//! The `cell_ifaces` set contains each cell interface. The `cell_src` set
//! contains each permitted interface and IPv6 prefix pair.
//!
//! The `nftables` crate sends a JSON ruleset to the `nft` program.

use ipnet::Ipv6Net;
use nftables::{
    batch::Batch,
    expr::{
        CT, Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField,
        Prefix, SetItem,
    },
    helper::{NftablesError, apply_ruleset},
    schema::{
        Chain, Element, NfListObject, Rule, Set, SetFlag, SetType,
        SetTypeValue, Table,
    },
    stmt::{Match, Operator, Statement},
    types::{NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;
use std::collections::HashSet;
use std::io;
use std::sync::Mutex;
use tracing::warn;

const TABLE_NAME: &str = "aurae";
const PREROUTING_CHAIN: &str = "source_filter";
const FORWARD_CHAIN: &str = "forward_accept";
const POSTROUTING_CHAIN: &str = "nat_postrouting";
const SET_CELL_IFACES: &str = "cell_ifaces";
const SET_CELL_SRC: &str = "cell_src";

/// Run before filter chains that use priority 0.
const FORWARD_PRIORITY: i32 = -5;
const PREROUTING_PRIORITY: i32 = -5;

/// `NF_IP_PRI_NAT_SRC` from `<linux/netfilter_ipv4.h>`.
const POSTROUTING_PRIORITY: i32 = 100;

const FAMILY: NfFamily = NfFamily::INet;

/// The configuration of the NAT ruleset: the cell pool and the WAN egress
/// interface. [`NatManager`] uses it to build the install batch and the
/// delete batch.
struct NatState {
    pool_v6: Ipv6Net,
    /// `None` if the host has no IPv6 default route. The base chain is
    /// still installed with the anti-spoof and cell-to-cell rules, but
    /// there is no egress and no masquerade.
    wan_iface: Option<String>,
}

impl NatState {
    fn new(pool_v6: Ipv6Net, wan_iface: Option<&str>) -> io::Result<Self> {
        let wan_iface = match wan_iface {
            Some(iface) => {
                if iface.is_empty() || iface.as_bytes().contains(&0) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "wan_iface is empty or contains a NUL byte",
                    ));
                }
                Some(iface.to_string())
            }
            None => None,
        };
        Ok(Self { pool_v6, wan_iface })
    }

    fn build_install(&self) -> Batch<'_> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Table(self.table()));
        batch.add(NfListObject::Set(Box::new(self.set_cell_ifaces())));
        batch.add(NfListObject::Set(Box::new(self.set_cell_src())));
        batch.add(NfListObject::Chain(self.prerouting_chain()));
        batch.add(NfListObject::Chain(self.forward_chain()));
        // Drop other network protocols before the IPv6 source check.
        batch.add(NfListObject::Rule(self.rule_drop_non_ipv6()));
        batch.add(NfListObject::Rule(self.rule_antispoof()));
        batch.add(NfListObject::Rule(self.rule_allow_cell_to_cell()));

        if let Some(wan) = self.wan_iface.as_deref() {
            batch.add(NfListObject::Chain(self.postrouting_chain()));
            batch.add(NfListObject::Rule(self.rule_allow_egress(wan)));
            batch.add(NfListObject::Rule(self.rule_allow_return(wan)));
            batch.add(NfListObject::Rule(self.rule_masquerade(wan)));
        }
        batch
    }

    /// The set of the host-side primaries of all live cells. It limits the
    /// anti-spoof rule to cell traffic. Thus the rule cannot match a WAN
    /// return flow or other forwarded traffic on the host.
    fn set_cell_ifaces(&self) -> Set<'_> {
        Set {
            family: FAMILY,
            table: TABLE_NAME.into(),
            name: SET_CELL_IFACES.into(),
            set_type: SetTypeValue::Single(SetType::Ifname),
            ..default_set()
        }
    }

    /// The set of the permitted `(cell primary, delegated prefix)` pairs.
    /// The `interval` flag lets the address part hold a prefix and not only
    /// one address. Thus a VM cell can receive a full prefix.
    fn set_cell_src(&self) -> Set<'_> {
        Set {
            family: FAMILY,
            table: TABLE_NAME.into(),
            name: SET_CELL_SRC.into(),
            set_type: SetTypeValue::Concatenated(Cow::Borrowed(&[
                SetType::Ifname,
                SetType::Ipv6Addr,
            ])),
            flags: Some(HashSet::from([SetFlag::Interval])),
            ..default_set()
        }
    }

    /// The delete batch is an `add table` and a `delete table` in one nft
    /// transaction. The `add` creates the table if it is absent and does
    /// nothing if it is present. Thus the target of the `delete` always
    /// exists, and the batch cannot fail with "no such table". It is not
    /// possible to identify that error after the fact, because the
    /// `nftables` crate starts `nft` with an inherited stderr. Therefore
    /// `NftablesError::NftFailed.stderr` is always empty.
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

    fn prerouting_chain(&self) -> Chain<'_> {
        Chain {
            family: FAMILY,
            table: TABLE_NAME.into(),
            name: PREROUTING_CHAIN.into(),
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Prerouting),
            prio: Some(PREROUTING_PRIORITY),
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

    /// Build a rule with the given statements for `chain`.
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

    /// Drop non-IPv6 packets from a cell interface.
    fn rule_drop_non_ipv6(&self) -> Rule<'_> {
        self.rule(
            PREROUTING_CHAIN,
            vec![
                match_set(
                    Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::Iifname,
                    })),
                    SET_CELL_IFACES,
                    Operator::EQ,
                ),
                match_meta(MetaKey::Nfproto, "ipv6", Operator::NEQ),
                Statement::Drop(None),
            ],
        )
    }

    /// Drop an IPv6 source that is not assigned to the input interface.
    fn rule_antispoof(&self) -> Rule<'_> {
        self.rule(
            PREROUTING_CHAIN,
            vec![
                match_set(
                    Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::Iifname,
                    })),
                    SET_CELL_IFACES,
                    Operator::EQ,
                ),
                match_set(
                    Expression::Named(NamedExpression::Concat(vec![
                        Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::Iifname,
                        })),
                        ip6_field("saddr"),
                    ])),
                    SET_CELL_SRC,
                    Operator::NEQ,
                ),
                Statement::Drop(None),
            ],
        )
    }

    /// Forward rule. It accepts cell-to-cell traffic in the pool.
    ///
    /// Without this rule, cell-to-cell traffic matches no other rule and
    /// leaves the chain at its end. The other base chains on the forward
    /// hook then decide. On a host with a forward chain that has a deny
    /// policy, the cells cannot reach each other.
    fn rule_allow_cell_to_cell(&self) -> Rule<'_> {
        self.rule(
            FORWARD_CHAIN,
            vec![
                match_addr("saddr", self.pool_v6, Operator::EQ),
                match_addr("daddr", self.pool_v6, Operator::EQ),
                Statement::Accept(None),
            ],
        )
    }

    /// Forward rule. It accepts the egress traffic from the cell pool to
    /// the WAN.
    fn rule_allow_egress<'a>(&self, wan: &'a str) -> Rule<'a> {
        self.rule(
            FORWARD_CHAIN,
            vec![
                match_addr("saddr", self.pool_v6, Operator::EQ),
                match_meta(MetaKey::Oifname, wan, Operator::EQ),
                Statement::Accept(None),
            ],
        )
    }

    /// Forward rule. It accepts the return traffic from the WAN to the cell
    /// pool if conntrack reports an established or related flow.
    fn rule_allow_return<'a>(&self, wan: &'a str) -> Rule<'a> {
        self.rule(
            FORWARD_CHAIN,
            vec![
                match_addr("daddr", self.pool_v6, Operator::EQ),
                match_meta(MetaKey::Iifname, wan, Operator::EQ),
                match_ct_state_established_or_related(),
                Statement::Accept(None),
            ],
        )
    }

    /// Postrouting rule. It masquerades the pool on the WAN interface.
    fn rule_masquerade<'a>(&self, wan: &'a str) -> Rule<'a> {
        self.rule(
            POSTROUTING_CHAIN,
            vec![
                match_addr("saddr", self.pool_v6, Operator::EQ),
                match_meta(MetaKey::Oifname, wan, Operator::EQ),
                Statement::Masquerade(None),
            ],
        )
    }

    /// The two elements of one cell, one for each set. A single batch
    /// applies them. The two sets always list the same cells.
    fn cell_elements<'a>(
        &self,
        primary: &'a str,
        delegated: Ipv6Net,
    ) -> [Element<'a>; 2] {
        [
            Element {
                family: FAMILY,
                table: TABLE_NAME.into(),
                name: SET_CELL_IFACES.into(),
                elem: Cow::Owned(vec![Expression::String(Cow::Borrowed(
                    primary,
                ))]),
            },
            Element {
                family: FAMILY,
                table: TABLE_NAME.into(),
                name: SET_CELL_SRC.into(),
                elem: Cow::Owned(vec![Expression::Named(
                    NamedExpression::Concat(vec![
                        Expression::String(Cow::Borrowed(primary)),
                        prefix_expr(delegated),
                    ]),
                )]),
            },
        ]
    }

    fn build_bind_cell<'a>(
        &self,
        primary: &'a str,
        delegated: Ipv6Net,
    ) -> Batch<'a> {
        let mut batch = Batch::new();
        for elem in self.cell_elements(primary, delegated) {
            batch.add(NfListObject::Element(elem));
        }
        batch
    }

    /// Remove the elements of one cell. The batch adds each element before
    /// it deletes the element, as the table batch does. `nft` fails the
    /// full transaction if `delete element` finds no element, and a
    /// teardown can run two times.
    fn build_unbind_cell<'a>(
        &self,
        primary: &'a str,
        delegated: Ipv6Net,
    ) -> Batch<'a> {
        let mut batch = Batch::new();
        for elem in self.cell_elements(primary, delegated) {
            batch.add(NfListObject::Element(elem.clone()));
            batch.delete(NfListObject::Element(elem));
        }
        batch
    }
}

/// A `Set` with default values for all fields except the name and the
/// type.
fn default_set<'a>() -> Set<'a> {
    Set {
        family: FAMILY,
        table: TABLE_NAME.into(),
        name: "".into(),
        handle: None,
        set_type: SetTypeValue::Single(SetType::Ifname),
        policy: None,
        flags: None,
        elem: None,
        timeout: None,
        gc_interval: None,
        size: None,
        comment: None,
    }
}

fn match_meta<'a>(key: MetaKey, value: &'a str, op: Operator) -> Statement<'a> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta { key })),
        right: Expression::String(Cow::Borrowed(value)),
        op,
    })
}

/// The `ip6 <field>` payload expression. `field` is `"saddr"` or
/// `"daddr"`.
fn ip6_field<'a>(field: &'static str) -> Expression<'a> {
    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField { protocol: "ip6".into(), field: field.into() },
    )))
}

/// An IPv6 prefix as an nft `prefix` expression.
fn prefix_expr<'a>(net: Ipv6Net) -> Expression<'a> {
    Expression::Named(NamedExpression::Prefix(Prefix {
        addr: Box::new(Expression::String(net.network().to_string().into())),
        len: u32::from(net.prefix_len()),
    }))
}

/// Match `ip6 <field>` against the configured pool, with the given
/// operator. `field` is `"saddr"` or `"daddr"`.
fn match_addr<'a>(
    field: &'static str,
    pool: Ipv6Net,
    op: Operator,
) -> Statement<'a> {
    Statement::Match(Match {
        left: ip6_field(field),
        right: prefix_expr(pool),
        op,
    })
}

/// Match `left` against the named set `name`. In the JSON form of nft, a
/// set reference is the name with the prefix `@`.
fn match_set<'a>(
    left: Expression<'a>,
    set_name: &str,
    op: Operator,
) -> Statement<'a> {
    Statement::Match(Match {
        left,
        right: Expression::String(Cow::Owned(format!("@{set_name}"))),
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

/// Controls the lifecycle of the nftables rules for cell networking.
/// [`NatManager::new`] builds it. The manager starts in the uninstalled
/// condition and records its own state.
///
/// [`Self::install`] is idempotent. It deletes an existing `inet aurae`
/// table before it installs the new one. Thus a second call with different
/// parameters replaces the ruleset. [`Self::uninstall`] does nothing if no
/// ruleset is installed. The internal `Mutex` serializes the install and
/// uninstall operations. `is_installed` holds the lock for a short time.
///
/// [`Self::bind_cell_source`] and [`Self::unbind_cell_source`] add and
/// remove the elements of one cell.
///
/// The `nft` binary must be in the `$PATH` of the host.
pub(crate) struct NatManager {
    state: Mutex<Option<NatState>>,
}

impl NatManager {
    pub(crate) fn new() -> Self {
        Self { state: Mutex::new(None) }
    }

    /// Install the ruleset. The function first deletes an existing `inet
    /// aurae` table. Thus it is correct for a first install, for the
    /// recovery of a table from a previous daemon, and for a reconfigure.
    /// The delete also removes the set elements of the live cells, and the
    /// caller must bind those cells again.
    ///
    /// `wan_iface` is `None` if the host has no IPv6 default route. The
    /// anti-spoof and cell-to-cell rules are still installed. Only the
    /// egress and masquerade rules are absent.
    pub(crate) fn install(
        &self,
        pool_v6: Ipv6Net,
        wan_iface: Option<&str>,
    ) -> io::Result<()> {
        let new_state = NatState::new(pool_v6, wan_iface)?;
        let mut guard = self.state.lock().expect("nat mutex poisoned");

        // Delete an existing `inet aurae` table. The delete batch is
        // idempotent. It is successful also if no table exists. A
        // failure here shows a real nft problem.
        if let Err(e) = apply_batch(new_state.build_delete()) {
            return Err(io_err("delete prior nft table", e));
        }

        if let Err(e) = apply_batch(new_state.build_install()) {
            // Remove a partial installation.
            if let Err(cleanup_err) = apply_batch(new_state.build_delete()) {
                warn!(
                    "NAT install failed and cleanup also failed: \
                     install={e}, cleanup={cleanup_err}. Operator may \
                     need to `nft delete table inet aurae`."
                );
                *guard = Some(new_state);
            } else {
                *guard = None;
            }
            return Err(io_err("install nft ruleset", e));
        }

        *guard = Some(new_state);
        Ok(())
    }

    /// Remove the ruleset. The function does nothing if no ruleset is
    /// installed. It is also safe if the operator deleted the table
    /// before, because the delete batch is idempotent.
    pub(crate) fn uninstall(&self) -> io::Result<()> {
        let mut guard = self.state.lock().expect("nat mutex poisoned");
        let Some(state) = guard.as_ref() else { return Ok(()) };
        apply_batch(state.build_delete())
            .map_err(|e| io_err("uninstall nft ruleset", e))?;
        *guard = None;
        Ok(())
    }

    pub(crate) fn is_installed(&self) -> bool {
        self.state.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Bind the host-side primary of a cell to its delegated prefix. The
    /// forward chain then accepts the traffic of that cell and drops all
    /// other traffic with the same source.
    ///
    /// `create_cell_interface` calls this function before the peer enters
    /// the network namespace of the cell. Thus an unbound cell cannot send a packet.
    /// The function does nothing if no ruleset is installed, because the
    /// caller does not create a cell in that condition.
    pub(crate) fn bind_cell_source(
        &self,
        primary: &str,
        delegated: Ipv6Net,
    ) -> io::Result<()> {
        let guard = self.state.lock().expect("nat mutex poisoned");
        let Some(state) = guard.as_ref() else { return Ok(()) };
        apply_batch(state.build_bind_cell(primary, delegated))
            .map_err(|e| io_err("bind cell source", e))
    }

    /// Remove the binding of a cell. The function is idempotent. a
    /// teardown path can run more than one time.
    pub(crate) fn unbind_cell_source(
        &self,
        primary: &str,
        delegated: Ipv6Net,
    ) -> io::Result<()> {
        let guard = self.state.lock().expect("nat mutex poisoned");
        let Some(state) = guard.as_ref() else { return Ok(()) };
        apply_batch(state.build_unbind_cell(primary, delegated))
            .map_err(|e| io_err("unbind cell source", e))
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
    const CELL_PRIMARY: &str = "nk-a1b2c3d4";

    fn test_state() -> NatState {
        NatState::new(test_pool_v6(), Some(TEST_IFACE))
            .expect("valid test iface")
    }

    /// Render a batch in the form that `nft` receives. The tests assert on
    /// this document and not on the typed model. Thus the tests stay short,
    /// and a diff shows the change of the ruleset.
    fn render(batch: Batch<'_>) -> String {
        serde_json::to_string_pretty(&batch.to_nftables())
            .expect("ruleset serializes")
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

    #[test]
    fn cell_binding_is_a_noop_when_nothing_is_installed() {
        let m = NatManager::new();
        let net: Ipv6Net = "fd00:ae::2/128".parse().expect("net");
        m.bind_cell_source(CELL_PRIMARY, net).expect("bind is a no-op");
        m.unbind_cell_source(CELL_PRIMARY, net).expect("unbind is a no-op");
    }

    // ---- NatState construction ----

    #[test]
    fn state_rejects_nul_byte_iface() {
        assert!(NatState::new(test_pool_v6(), Some("eth0\0bad")).is_err());
    }

    #[test]
    fn state_rejects_empty_iface() {
        assert!(NatState::new(test_pool_v6(), Some("")).is_err());
    }

    #[test]
    fn state_accepts_absent_wan() {
        assert!(NatState::new(test_pool_v6(), None).is_ok());
    }

    // ---- Ruleset shape ----

    /// The rule that gives the security. Two conditions apply. The drop is
    /// limited to the cell interfaces. It cannot match WAN return
    /// traffic. The drop also uses the pair `iifname . saddr`, because a
    /// match with pool granularity would let one cell forge the address of
    /// a sibling cell.
    #[test]
    fn antispoof_rule_binds_each_cell_to_its_own_prefix() {
        let rendered = render(test_state().build_install());
        assert!(
            rendered.contains(r#""@cell_ifaces""#),
            "anti-spoof must be scoped to cell interfaces:\n{rendered}"
        );
        assert!(
            rendered.contains(r#""@cell_src""#),
            "anti-spoof must key on the (iifname, saddr) pair:\n{rendered}"
        );
        assert!(
            rendered.contains(r#""concat""#),
            "the cell_src lookup must be a concatenation:\n{rendered}"
        );
        // The drop rule must come before each accept rule. If not, an
        // accept rule can pass spoofed traffic.
        let drop_at = rendered.find(r#""drop""#).expect("a drop rule exists");
        let accept_at =
            rendered.find(r#""accept""#).expect("an accept rule exists");
        assert!(
            drop_at < accept_at,
            "the per-cell drop must be evaluated before any accept:\n{rendered}"
        );
    }

    #[test]
    fn source_filter_runs_in_prerouting() {
        let state = test_state();
        let nft = state.build_install().to_nftables();
        let chain = nft.objects.iter().find_map(|object| match object {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(chain)))
                if chain.name == PREROUTING_CHAIN =>
            {
                Some(chain)
            }
            _ => None,
        });
        let chain = chain.expect("source filter chain");
        assert_eq!(chain.hook, Some(NfHook::Prerouting));
    }

    #[test]
    fn source_filter_drops_non_ipv6_cell_traffic() {
        let state = test_state();
        let nft = state.build_install().to_nftables();
        let rule = nft.objects.iter().find_map(|object| match object {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule)))
                if rule.chain == PREROUTING_CHAIN
                    && rule.expr.iter().any(|statement| {
                        matches!(statement, Statement::Match(Match {
                            left: Expression::Named(NamedExpression::Meta(Meta {
                                key: MetaKey::Nfproto,
                            })),
                            right: Expression::String(value),
                            op: Operator::NEQ,
                        }) if value == "ipv6")
                    }) =>
            {
                Some(rule)
            }
            _ => None,
        });
        let rule = rule.expect("non-IPv6 drop rule");
        assert!(matches!(rule.expr.last(), Some(Statement::Drop(None))));
    }

    /// Cell-to-cell traffic needs an accept rule. Without it the traffic
    /// matches no rule and leaves the chain at its end. The other base
    /// chains on the forward hook then decide.
    #[test]
    fn install_accepts_cell_to_cell_within_the_pool() {
        let state = test_state();
        let nft = state.build_install().to_nftables();
        let rule = nft
            .objects
            .iter()
            .filter_map(|o| match o {
                NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r))) => {
                    Some(r)
                }
                _ => None,
            })
            .find(|r| {
                r.expr.len() == 3
                    && matches!(r.expr[2], Statement::Accept(None))
                    && matches!(&r.expr[0], Statement::Match(m)
                        if is_pool_match(m, "saddr"))
                    && matches!(&r.expr[1], Statement::Match(m)
                        if is_pool_match(m, "daddr"))
            });
        assert!(
            rule.is_some(),
            "no `saddr @pool && daddr @pool accept` rule found"
        );
    }

    fn is_pool_match(m: &Match<'_>, field: &str) -> bool {
        let Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            PayloadField { protocol, field: f },
        ))) = &m.left
        else {
            return false;
        };
        protocol.as_ref() == "ip6" && f.as_ref() == field
    }

    /// A host with no IPv6 default route still receives the anti-spoof and
    /// cell-to-cell rules. Only the egress and masquerade rules are absent.
    /// If not, a host without v6 egress would run cells with no source
    /// binding.
    #[test]
    fn install_without_wan_keeps_antispoof_and_drops_egress() {
        let state =
            NatState::new(test_pool_v6(), None).expect("wan-less state");
        let rendered = render(state.build_install());
        assert!(rendered.contains(r#""@cell_src""#), "{rendered}");
        assert!(
            !rendered.contains("masquerade"),
            "no WAN means no masquerade:\n{rendered}"
        );
        assert!(
            !rendered.contains(POSTROUTING_CHAIN),
            "no WAN means no postrouting chain:\n{rendered}"
        );
    }

    #[test]
    fn install_with_wan_adds_masquerade_and_conntrack_return() {
        let rendered = render(test_state().build_install());
        assert!(rendered.contains("masquerade"), "{rendered}");
        assert!(rendered.contains(POSTROUTING_CHAIN), "{rendered}");
        assert!(rendered.contains("established"), "{rendered}");
        assert!(rendered.contains("related"), "{rendered}");
    }

    #[test]
    fn install_declares_both_sets_with_interval_on_the_pair() {
        let state = test_state();
        let nft = state.build_install().to_nftables();
        let sets: Vec<&Set<'_>> = nft
            .objects
            .iter()
            .filter_map(|o| match o {
                NfObject::CmdObject(NfCmd::Add(NfListObject::Set(s))) => {
                    Some(&**s)
                }
                _ => None,
            })
            .collect();
        assert_eq!(sets.len(), 2, "cell_ifaces and cell_src");

        let ifaces = sets
            .iter()
            .find(|s| s.name == SET_CELL_IFACES)
            .expect("cell_ifaces set");
        assert_eq!(ifaces.set_type, SetTypeValue::Single(SetType::Ifname));

        let src =
            sets.iter().find(|s| s.name == SET_CELL_SRC).expect("cell_src set");
        assert_eq!(
            src.set_type,
            SetTypeValue::Concatenated(Cow::Borrowed(&[
                SetType::Ifname,
                SetType::Ipv6Addr
            ]))
        );
        // The `interval` flag lets the address part hold a prefix, which a
        // VM cell with a full delegated prefix needs.
        assert_eq!(
            src.flags,
            Some(HashSet::from([SetFlag::Interval])),
            "cell_src must be an interval set"
        );
    }

    // ---- Per-cell elements ----

    #[test]
    fn bind_adds_one_element_to_each_set() {
        let state = test_state();
        let net: Ipv6Net = "fd00:ae::2/128".parse().expect("net");
        let nft = state.build_bind_cell(CELL_PRIMARY, net).to_nftables();
        let adds: Vec<&Element<'_>> = nft
            .objects
            .iter()
            .filter_map(|o| match o {
                NfObject::CmdObject(NfCmd::Add(NfListObject::Element(e))) => {
                    Some(e)
                }
                _ => None,
            })
            .collect();
        assert_eq!(adds.len(), 2, "one element per set");
        assert!(adds.iter().any(|e| e.name == SET_CELL_IFACES));
        assert!(adds.iter().any(|e| e.name == SET_CELL_SRC));

        let rendered = render(state.build_bind_cell(CELL_PRIMARY, net));
        assert!(rendered.contains(CELL_PRIMARY), "{rendered}");
        assert!(rendered.contains("fd00:ae::2"), "{rendered}");
    }

    /// `nft` stops the full transaction if `delete element` finds no
    /// element, and a teardown can run two times. Thus unbind adds each
    /// element before it deletes the element, as the table delete does.
    #[test]
    fn unbind_adds_before_deleting_each_element() {
        let state = test_state();
        let net: Ipv6Net = "fd00:ae::2/128".parse().expect("net");
        let nft = state.build_unbind_cell(CELL_PRIMARY, net).to_nftables();
        let cmds: Vec<&str> = nft
            .objects
            .iter()
            .map(|o| match o {
                NfObject::CmdObject(NfCmd::Add(_)) => "add",
                NfObject::CmdObject(NfCmd::Delete(_)) => "delete",
                _ => "other",
            })
            .collect();
        assert_eq!(cmds, ["add", "delete", "add", "delete"]);
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
        for (obj, want_delete) in objs.iter().zip([false, true]) {
            let inner = match obj {
                NfObject::CmdObject(NfCmd::Add(inner)) if !want_delete => inner,
                NfObject::CmdObject(NfCmd::Delete(inner)) if want_delete => {
                    inner
                }
                other => panic!("unexpected object {other:?}"),
            };
            let NfListObject::Table(table) = inner else {
                panic!("expected a Table, got {inner:?}");
            };
            assert_eq!(table.family, FAMILY);
            assert_eq!(table.name, TABLE_NAME);
        }
    }
}
