//! Runtime filter-expression parser (0.25 Phase A4).
//!
//! A small, dependency-free recursive-descent parser from a Wireshark-ish
//! filter string to the **same** [`Predicate`] AST the typed builders produce.
//! So `packet().expr("tcp and dst port 443")` and
//! `packet().tcp().dst_port(443)` are identical — one AST, two frontends — and
//! both lower to the same userspace eval + kernel pushdown. This is the path
//! for filters that come from *outside* the binary (config, CLI, a control
//! plane), where a compile-time typed builder can't reach.
//!
//! We deliberately do **not** depend on `wirefilter-engine` (its crates.io
//! release is stale at 0.6.1/2019); the grammar here is small enough to own.
//!
//! ## Grammar
//!
//! ```text
//! expr    := or
//! or      := and ( ("or" | "||") and )*
//! and     := not ( ("and" | "&&") not )*
//! not     := ("not" | "!") not | primary
//! primary := "(" expr ")" | atom
//! atom    := "tcp" | "udp" | "icmp"
//!          | dir? "port" INT | dir? "host" IP | dir? "net" CIDR
//!          | "vlan" INT
//!          | "bytes" ">" INT | "packets" ">" INT
//!          | "tls.sni" "~" GLOB | "http.host" "~" GLOB | "dns.qname" "~" GLOB
//! dir     := "src" | "dst"
//! ```
//!
//! Tier-inappropriate atoms parse fine but simply never match at eval time
//! (e.g. `tls.sni` on the packet tier — the field is `None` there), mirroring
//! the userspace-`None`-is-false rule of [`Predicate::eval`].

use std::fmt;
use std::net::IpAddr;

use flowscope::L4Proto;

use super::predicate::{Atom, Glob, Predicate};
use crate::config::ipnet::IpNet;

/// A filter-expression parse error, with a short human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// What went wrong (e.g. `unexpected token "foo"`, `expected a port number`).
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "filter expression parse error: {}", self.message)
    }
}

impl std::error::Error for ParseError {}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Parse a filter expression into a [`Predicate`].
pub fn parse(input: &str) -> Result<Predicate, ParseError> {
    let tokens = tokenize(input);
    if tokens.is_empty() {
        // An empty filter matches everything (the unfiltered subscription).
        return Ok(Predicate::Always);
    }
    let mut p = Parser { tokens, pos: 0 };
    let pred = p.parse_or()?;
    if p.pos != p.tokens.len() {
        return Err(ParseError::new(format!(
            "unexpected trailing token {:?}",
            p.tokens[p.pos]
        )));
    }
    Ok(pred)
}

/// Split into whitespace-delimited tokens, with `(` `)` `!` `~` `>` always
/// standing alone (so `tls.sni~*.bank` and `(tcp)` tokenize correctly).
fn tokenize(input: &str) -> Vec<String> {
    let mut spaced = String::with_capacity(input.len() * 2);
    for ch in input.chars() {
        if matches!(ch, '(' | ')' | '!' | '~' | '>') {
            spaced.push(' ');
            spaced.push(ch);
            spaced.push(' ');
        } else {
            spaced.push(ch);
        }
    }
    spaced.split_whitespace().map(|s| s.to_string()).collect()
}

struct Parser {
    tokens: Vec<String>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.pos).map(|s| s.as_str())
    }

    fn advance(&mut self) -> Option<String> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    /// `lc` of the current token, for case-insensitive keyword matching.
    fn peek_lc(&self) -> Option<String> {
        self.peek().map(|s| s.to_ascii_lowercase())
    }

    fn parse_or(&mut self) -> Result<Predicate, ParseError> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek_lc().as_deref(), Some("or") | Some("||")) {
            self.advance();
            let rhs = self.parse_and()?;
            lhs = lhs.or(rhs);
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Predicate, ParseError> {
        let mut lhs = self.parse_not()?;
        while matches!(self.peek_lc().as_deref(), Some("and") | Some("&&")) {
            self.advance();
            let rhs = self.parse_not()?;
            lhs = lhs.and(rhs);
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Predicate, ParseError> {
        if matches!(self.peek_lc().as_deref(), Some("not") | Some("!")) {
            self.advance();
            return Ok(self.parse_not()?.negate());
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Predicate, ParseError> {
        if self.peek() == Some("(") {
            self.advance();
            let inner = self.parse_or()?;
            match self.advance().as_deref() {
                Some(")") => Ok(inner),
                _ => Err(ParseError::new("expected closing `)`")),
            }
        } else {
            self.parse_atom()
        }
    }

    fn parse_atom(&mut self) -> Result<Predicate, ParseError> {
        let tok = self
            .advance()
            .ok_or_else(|| ParseError::new("unexpected end of expression"))?;
        let lc = tok.to_ascii_lowercase();
        let atom = match lc.as_str() {
            "tcp" => Atom::Proto(L4Proto::Tcp),
            "udp" => Atom::Proto(L4Proto::Udp),
            "icmp" => Atom::Proto(L4Proto::Icmp),
            "vlan" => Atom::VlanId(self.expect_u16("a VLAN id")?),
            "port" => Atom::AnyPort(self.expect_u16("a port number")?),
            "host" => Atom::AnyHost(self.expect_ip()?),
            "net" => Atom::AnyNet(self.expect_net()?),
            "src" | "dst" => return self.parse_directional(&lc),
            "bytes" => {
                self.expect_gt()?;
                Atom::BytesOver(self.expect_u64("a byte count")?)
            }
            "packets" => {
                self.expect_gt()?;
                Atom::PacketsOver(self.expect_u64("a packet count")?)
            }
            "tls.sni" => Atom::SniGlob(self.expect_glob()?),
            "http.host" => Atom::HttpHostGlob(self.expect_glob()?),
            "dns.qname" => Atom::DnsQnameGlob(self.expect_glob()?),
            other => return Err(ParseError::new(format!("unexpected token {other:?}"))),
        };
        Ok(Predicate::Atom(atom))
    }

    /// `src`/`dst` followed by `port` / `host` / `net`.
    fn parse_directional(&mut self, dir: &str) -> Result<Predicate, ParseError> {
        let kind = self
            .advance()
            .ok_or_else(|| ParseError::new("expected `port`, `host`, or `net` after src/dst"))?
            .to_ascii_lowercase();
        let src = dir == "src";
        let atom = match kind.as_str() {
            "port" => {
                let p = self.expect_u16("a port number")?;
                if src {
                    Atom::SrcPort(p)
                } else {
                    Atom::DstPort(p)
                }
            }
            "host" => {
                let ip = self.expect_ip()?;
                if src {
                    Atom::SrcHost(ip)
                } else {
                    Atom::DstHost(ip)
                }
            }
            "net" => {
                let n = self.expect_net()?;
                if src {
                    Atom::SrcNet(n)
                } else {
                    Atom::DstNet(n)
                }
            }
            other => {
                return Err(ParseError::new(format!(
                    "expected `port`/`host`/`net` after {dir}, got {other:?}"
                )));
            }
        };
        Ok(Predicate::Atom(atom))
    }

    fn expect_u16(&mut self, what: &str) -> Result<u16, ParseError> {
        let t = self
            .advance()
            .ok_or_else(|| ParseError::new(format!("expected {what}")))?;
        t.parse::<u16>()
            .map_err(|_| ParseError::new(format!("expected {what}, got {t:?}")))
    }

    fn expect_u64(&mut self, what: &str) -> Result<u64, ParseError> {
        let t = self
            .advance()
            .ok_or_else(|| ParseError::new(format!("expected {what}")))?;
        t.parse::<u64>()
            .map_err(|_| ParseError::new(format!("expected {what}, got {t:?}")))
    }

    fn expect_ip(&mut self) -> Result<IpAddr, ParseError> {
        let t = self
            .advance()
            .ok_or_else(|| ParseError::new("expected an IP address"))?;
        t.parse::<IpAddr>()
            .map_err(|_| ParseError::new(format!("expected an IP address, got {t:?}")))
    }

    fn expect_net(&mut self) -> Result<IpNet, ParseError> {
        let t = self
            .advance()
            .ok_or_else(|| ParseError::new("expected a CIDR network"))?;
        t.parse::<IpNet>()
            .map_err(|_| ParseError::new(format!("expected a CIDR network, got {t:?}")))
    }

    fn expect_glob(&mut self) -> Result<Glob, ParseError> {
        match self.advance().as_deref() {
            Some("~") => {}
            _ => return Err(ParseError::new("expected `~` before a glob pattern")),
        }
        let t = self
            .advance()
            .ok_or_else(|| ParseError::new("expected a glob pattern after `~`"))?;
        Ok(Glob::new(t))
    }

    fn expect_gt(&mut self) -> Result<(), ParseError> {
        match self.advance().as_deref() {
            Some(">") => Ok(()),
            _ => Err(ParseError::new("expected `>` for a count comparison")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::subscription::builder::packet;

    fn p(s: &str) -> Predicate {
        parse(s).unwrap_or_else(|e| panic!("parse {s:?}: {e}"))
    }

    #[test]
    fn empty_is_always() {
        assert_eq!(parse("").unwrap(), Predicate::Always);
        assert_eq!(parse("   ").unwrap(), Predicate::Always);
    }

    #[test]
    fn protocol_and_port_atoms() {
        assert_eq!(p("tcp"), Predicate::Atom(Atom::Proto(L4Proto::Tcp)));
        assert_eq!(p("dst port 443"), Predicate::Atom(Atom::DstPort(443)));
        assert_eq!(p("src port 53"), Predicate::Atom(Atom::SrcPort(53)));
        assert_eq!(p("port 80"), Predicate::Atom(Atom::AnyPort(80)));
        assert_eq!(p("vlan 100"), Predicate::Atom(Atom::VlanId(100)));
    }

    #[test]
    fn host_net_count_l7_atoms() {
        assert_eq!(
            p("host 8.8.8.8"),
            Predicate::Atom(Atom::AnyHost("8.8.8.8".parse().unwrap()))
        );
        assert_eq!(
            p("src net 10.0.0.0/8"),
            Predicate::Atom(Atom::SrcNet("10.0.0.0/8".parse().unwrap()))
        );
        assert_eq!(
            p("bytes > 1048576"),
            Predicate::Atom(Atom::BytesOver(1048576))
        );
        assert_eq!(p("packets > 10"), Predicate::Atom(Atom::PacketsOver(10)));
        assert_eq!(
            p("tls.sni ~ *.bank"),
            Predicate::Atom(Atom::SniGlob(Glob::new("*.bank")))
        );
        assert_eq!(
            p("dns.qname ~ *.evil.test"),
            Predicate::Atom(Atom::DnsQnameGlob(Glob::new("*.evil.test")))
        );
    }

    #[test]
    fn precedence_and_binds_tighter_than_or() {
        // tcp and port 443 or udp  ==  (tcp AND 443) OR udp
        let got = p("tcp and dst port 443 or udp");
        let expect = Predicate::Atom(Atom::Proto(L4Proto::Tcp))
            .and(Predicate::Atom(Atom::DstPort(443)))
            .or(Predicate::Atom(Atom::Proto(L4Proto::Udp)));
        assert_eq!(got, expect);
    }

    #[test]
    fn parens_override_precedence() {
        // tcp and ( port 80 or port 443 )
        let got = p("tcp and ( dst port 80 or dst port 443 )");
        let expect = Predicate::Atom(Atom::Proto(L4Proto::Tcp))
            .and(Predicate::Atom(Atom::DstPort(80)).or(Predicate::Atom(Atom::DstPort(443))));
        assert_eq!(got, expect);
    }

    #[test]
    fn negation_and_symbols() {
        assert_eq!(
            p("not tcp"),
            Predicate::Atom(Atom::Proto(L4Proto::Tcp)).negate()
        );
        // `!` and `&&`/`||` aliases.
        let a = p("udp && ! dst port 53");
        let b = Predicate::Atom(Atom::Proto(L4Proto::Udp))
            .and(Predicate::Atom(Atom::DstPort(53)).negate());
        assert_eq!(a, b);
    }

    #[test]
    fn case_insensitive_keywords() {
        assert_eq!(p("TCP AND DST PORT 443"), p("tcp and dst port 443"));
    }

    #[test]
    fn expr_equals_typed_builder() {
        // The headline property: the string and typed frontends produce the
        // identical AST.
        let from_expr = p("tcp and dst port 443");
        let from_builder = packet().tcp().dst_port(443).into_predicate();
        assert_eq!(from_expr, from_builder);
    }

    #[test]
    fn errors_are_reported_not_panicked() {
        assert!(parse("tcp and").is_err()); // dangling operator → empty rhs atom
        assert!(parse("port").is_err()); // missing number
        assert!(parse("port abc").is_err()); // bad number
        assert!(parse("host nope").is_err()); // bad ip
        assert!(parse("( tcp").is_err()); // unbalanced paren
        assert!(parse("frobnicate").is_err()); // unknown token
        assert!(parse("tcp udp").is_err()); // trailing token (no operator)
    }
}
