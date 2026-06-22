//! Issue #29: passive lateral-movement / Active Directory visibility.
//!
//! Surfaces the four flowscope 0.18 AD protocols through the Monitor and
//! emits an anomaly for each high-signal lateral-movement indicator:
//!
//!   * **SMB** (445) — access to an admin share (C$/ADMIN$/IPC$) or a
//!     well-known abused named pipe (svcctl/lsarpc/samr/…), plus DCE-RPC binds
//!     to the `drsuapi` interface used by DCSync.
//!   * **Kerberos** (88) — a TGS-REQ negotiating RC4-HMAC (Kerberoasting,
//!     T1558.003) and pre-auth failures (password spray / enumeration).
//!   * **LDAP** (389) — a `servicePrincipalName` search (GetUserSPNs /
//!     BloodHound, the Kerberoast prerequisite) and cleartext Simple binds.
//!   * **RDP** (3389) — the targeted `mstshash=` cookie username and NLA
//!     (CredSSP) downgrades.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_lateral_movement \
//!     --features "tokio,ad-protocols,emit" -- eth0
//! ```
//!
//! All four parsers are passive and metadata-only — no payload decryption,
//! no active probing.

use std::time::Duration;

use flowscope::kerberos::KerberosMessage;
use flowscope::ldap::LdapMessage;
use flowscope::rdp::RdpMessage;
use flowscope::smb::SmbMessage;
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    Monitor::builder()
        .interface(&iface)
        .name("lateral-movement")
        // ── SMB ────────────────────────────────────────────────────────────
        .protocol::<Smb>()
        .on_ctx::<Smb>(|m: &SmbMessage, ctx: &mut Ctx<'_>| {
            if m.tree_connect_is_admin_share
                && let Some(path) = &m.tree_connect_path
            {
                ctx.emit("SmbAdminShareAccess", Severity::Warning)
                    .with("share", path.clone())
                    .emit();
            }
            if m.create_is_admin_named_pipe
                && let Some(path) = &m.create_path
            {
                ctx.emit("SmbAbusedNamedPipe", Severity::Warning)
                    .with("pipe", path.clone())
                    .emit();
            }
            for uuid in &m.dcerpc_bind_uuids {
                if uuid.well_known_name() == Some("drsuapi") {
                    ctx.emit("SmbDcsyncBind", Severity::Critical)
                        .with("interface", "drsuapi")
                        .emit();
                }
            }
            Ok(())
        })
        // ── Kerberos ───────────────────────────────────────────────────────
        .protocol::<Kerberos>()
        .on_ctx::<Kerberos>(|m: &KerberosMessage, ctx: &mut Ctx<'_>| {
            if m.kerberoast_suspect {
                ctx.emit("KerberoastSuspect", Severity::Warning)
                    .with("realm", m.realm.clone())
                    .with("sname", m.sname.clone().unwrap_or_default())
                    .emit();
            }
            if let Some(code) = &m.error_code
                && code.is_brute_force_signal()
            {
                ctx.emit("KerberosBruteForceSignal", Severity::Warning)
                    .with("error", format!("{code:?}"))
                    .with("cname", m.cname.clone().unwrap_or_default())
                    .emit();
            }
            Ok(())
        })
        // ── LDAP ───────────────────────────────────────────────────────────
        .protocol::<Ldap>()
        .on_ctx::<Ldap>(|m: &LdapMessage, ctx: &mut Ctx<'_>| {
            if m.search_attributes_spn_query {
                ctx.emit("LdapSpnEnumeration", Severity::Warning)
                    .with("base", m.search_base.clone().unwrap_or_default())
                    .emit();
            }
            Ok(())
        })
        // ── RDP ────────────────────────────────────────────────────────────
        .protocol::<Rdp>()
        .on_ctx::<Rdp>(|m: &RdpMessage, ctx: &mut Ctx<'_>| {
            if let RdpMessage::ConnectionRequest {
                cookie_username: Some(user),
                ..
            } = m
            {
                ctx.emit("RdpTargetUsername", Severity::Info)
                    .with("username", user.clone())
                    .emit();
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
