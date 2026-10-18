//! [`SyslogSink`] — an RFC 5424 syslog adapter for the [`AnomalySink`]
//! chain.
//!
//! Each anomaly is rendered as one RFC 5424 syslog line and written to a
//! `W: Write + Send` (a TCP/UDS stream to a collector, a file, stdout for
//! a sidecar to forward, …). Hand-rolled — **no dependencies** — mirroring
//! the [`EveSink<W>`](crate::anomaly::EveSink) shape.
//!
//! The wire format ([RFC 5424] §6):
//!
//! ```text
//! <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
//! ```
//!
//! - `PRI` = `facility * 8 + severity` (severity per the netring →
//!   syslog map below).
//! - `1` = the RFC 5424 version.
//! - `TIMESTAMP` = the anomaly's timestamp as RFC 3339 (UTC, `…Z`), to the
//!   microsecond (RFC 5424 allows at most 6 fractional digits).
//! - `MSGID` = the detector's `kind` slug.
//! - `SD` = one structured-data element `[netring@<PEN> …]` carrying the
//!   endpoints (`src="ip:port" dst="ip:port" proto="TCP"` — the flow's
//!   initiator as `src` when the emitter knew it), or else the key's
//!   `Debug` text as `key="…"`, + observation/metric params; `-` when
//!   empty.
//! - `MSG` = a short human-readable summary.
//!
//! Lines are newline-framed. Control characters in SD values and the MSG
//! (observation values can come off the wire) are written as `\xNN`, so
//! no value can end a record early.
//!
//! Severity map (netring → RFC 5424 numeric severity):
//! `Critical → 2` (crit), `Error → 3` (err), `Warning → 4` (warning),
//! `Info → 6` (info).
//!
//! The default enterprise number is `32473`, the [RFC 5612] number IANA
//! reserves for documentation/examples — override with
//! [`SyslogSink::enterprise_id`] once you have a real PEN.
//!
//! [RFC 5424]: https://www.rfc-editor.org/rfc/rfc5424
//! [RFC 5612]: https://www.rfc-editor.org/rfc/rfc5612

use std::borrow::Cow;
use std::io::Write;

use flowscope::Timestamp;

use crate::anomaly::Severity;
use crate::anomaly::sink::{AnomalyRecord, AnomalySink, endpoint_text};

/// RFC 5424 facility (§6.2.1). Only the values that make sense for an
/// application emitting security telemetry are surfaced; the numeric code
/// is `facility << 3` in the PRI computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyslogFacility {
    /// `user` (1) — generic user-level messages.
    User,
    /// `daemon` (3) — system daemons.
    Daemon,
    /// `security`/`auth` (4) — security/authorization messages.
    Auth,
    /// `local0` (16) — the default; the reserved "local use" range is the
    /// conventional home for application telemetry.
    #[default]
    Local0,
    /// `local1` (17).
    Local1,
    /// `local2` (18).
    Local2,
    /// `local3` (19).
    Local3,
    /// `local4` (20).
    Local4,
    /// `local5` (21).
    Local5,
    /// `local6` (22).
    Local6,
    /// `local7` (23).
    Local7,
}

impl SyslogFacility {
    /// The numeric facility code (0–23).
    pub const fn code(self) -> u8 {
        match self {
            SyslogFacility::User => 1,
            SyslogFacility::Daemon => 3,
            SyslogFacility::Auth => 4,
            SyslogFacility::Local0 => 16,
            SyslogFacility::Local1 => 17,
            SyslogFacility::Local2 => 18,
            SyslogFacility::Local3 => 19,
            SyslogFacility::Local4 => 20,
            SyslogFacility::Local5 => 21,
            SyslogFacility::Local6 => 22,
            SyslogFacility::Local7 => 23,
        }
    }
}

/// The RFC 5424 numeric severity for a netring [`Severity`].
const fn syslog_severity(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 2,
        Severity::Error => 3,
        Severity::Warning => 4,
        Severity::Info => 6,
    }
}

/// An [`AnomalySink`] that writes one RFC 5424 syslog line per anomaly to
/// a `W: Write + Send`. See the [module docs](self) for the wire format.
///
/// Construct via [`SyslogSink::new`] (then chain the `app_name` /
/// `hostname` / `facility` / `enterprise_id` setters) or
/// [`SyslogSink::stdout`].
pub struct SyslogSink<W: Write + Send> {
    writer: W,
    app_name: Cow<'static, str>,
    hostname: Cow<'static, str>,
    procid: Cow<'static, str>,
    facility: SyslogFacility,
    enterprise_id: Cow<'static, str>,
    /// Reused across emits to avoid per-line allocation churn.
    scratch: String,
}

impl<W: Write + Send> SyslogSink<W> {
    /// Wrap `writer`. Defaults: app-name `netring`, hostname `-` (the
    /// NILVALUE — let the collector stamp it), procid `-`, facility
    /// `local0`, enterprise `32473`.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            app_name: Cow::Borrowed("netring"),
            hostname: Cow::Borrowed("-"),
            procid: Cow::Borrowed("-"),
            facility: SyslogFacility::Local0,
            enterprise_id: Cow::Borrowed("32473"),
            scratch: String::with_capacity(256),
        }
    }

    /// Set the `APP-NAME` field (default `netring`).
    pub fn app_name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.app_name = name.into();
        self
    }

    /// Set the `HOSTNAME` field (default `-`, the NILVALUE).
    pub fn hostname(mut self, host: impl Into<Cow<'static, str>>) -> Self {
        self.hostname = host.into();
        self
    }

    /// Set the `PROCID` field (default `-`). A pid or worker id.
    pub fn procid(mut self, procid: impl Into<Cow<'static, str>>) -> Self {
        self.procid = procid.into();
        self
    }

    /// Set the syslog facility (default [`SyslogFacility::Local0`]).
    pub fn facility(mut self, facility: SyslogFacility) -> Self {
        self.facility = facility;
        self
    }

    /// Set the structured-data enterprise number (the `@<PEN>` of the
    /// SD-ID; default `32473`, the RFC 5612 documentation PEN).
    pub fn enterprise_id(mut self, pen: impl Into<Cow<'static, str>>) -> Self {
        self.enterprise_id = pen.into();
        self
    }

    /// Consume the sink and recover the inner writer (tests read back the
    /// emitted bytes via a `Vec<u8>` writer).
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl SyslogSink<std::io::Stdout> {
    /// `SyslogSink::stdout()` — emit lines on stdout for a log-shipper
    /// sidecar to pick up.
    pub fn stdout() -> Self {
        Self::new(std::io::stdout())
    }
}

/// Render one RFC 5424 line into `out`. Pure (no I/O) so it's directly
/// golden-testable. `out` is cleared first.
fn render_rfc5424(
    out: &mut String,
    facility: SyslogFacility,
    app_name: &str,
    hostname: &str,
    procid: &str,
    enterprise_id: &str,
    record: &AnomalyRecord<'_>,
) {
    use std::fmt::Write as _;

    let (severity, kind, ts) = (record.severity, record.kind, record.ts);
    let (observations, metrics) = (record.observations, record.metrics);
    out.clear();
    let pri = (facility.code() as u16) * 8 + syslog_severity(severity) as u16;

    // HEADER: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
    let _ = write!(out, "<{pri}>1 ");
    push_timestamp(out, ts);
    let _ = write!(
        out,
        " {host} {app} {procid} {msgid} ",
        host = nilable(hostname),
        app = nilable(app_name),
        procid = nilable(procid),
        msgid = nilable(kind),
    );

    // STRUCTURED-DATA: one element, or `-` when there's nothing to carry.
    let has_sd = record.endpoints.is_some()
        || record.key.is_some()
        || !observations.is_empty()
        || !metrics.is_empty();
    if has_sd {
        let _ = write!(out, "[netring@{enterprise_id}");
        if let Some(e) = record.endpoints {
            // Addresses and protocol labels hold no character SD escaping
            // touches (`"`, `\`, `]`, controls).
            let _ = write!(
                out,
                " src=\"{}\" dst=\"{}\"",
                endpoint_text(e.src_ip, e.src_port),
                endpoint_text(e.dest_ip, e.dest_port)
            );
            if let Some(p) = e.proto {
                let _ = write!(out, " proto=\"{p}\"");
            }
        } else if let Some(k) = record.key {
            out.push_str(" key=\"");
            // Use the Debug rendering of the key; escape per RFC 5424.
            let mut keybuf = String::new();
            let _ = write!(keybuf, "{k:?}");
            push_sd_escaped(out, &keybuf);
            out.push('"');
        }
        for (label, value) in observations {
            let _ = write!(out, " {label}=\"");
            push_sd_escaped(out, value);
            out.push('"');
        }
        for (label, value) in metrics {
            let _ = write!(out, " {label}=\"{value}\"");
        }
        out.push(']');
    } else {
        out.push('-');
    }

    // MSG: a short human summary after a single space.
    let _ = write!(out, " {kind}");
    for (label, value) in observations {
        let _ = write!(out, " {label}=");
        push_control_escaped(out, value);
    }
}

/// Append `ts` as an RFC 5424 TIMESTAMP: RFC 3339 UTC with microseconds
/// (TIME-SECFRAC is `1*6DIGIT`, §6.2.3) — the nanoseconds truncated.
fn push_timestamp(out: &mut String, ts: Timestamp) {
    use std::fmt::Write as _;
    // `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`, fixed width for whole seconds.
    let _ = Timestamp::new(ts.sec, 0).write_iso8601(out);
    out.truncate(out.len() - ".000000000Z".len());
    let _ = write!(out, ".{:06}Z", (ts.nsec / 1_000).min(999_999));
}

/// RFC 5424 NILVALUE substitution: an empty field becomes `-`.
fn nilable(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

/// Append `s` to `out`, escaping the three characters RFC 5424 §6.3.3
/// requires inside a PARAM-VALUE: `"`, `\`, and `]` — and control
/// characters, as for the MSG ([`push_control_escaped`]).
fn push_sd_escaped(out: &mut String, s: &str) {
    for ch in s.chars() {
        if matches!(ch, '"' | '\\' | ']') {
            out.push('\\');
        }
        push_char_escaped(out, ch);
    }
}

/// Append `s` to `out` with every control character (C0, DEL, C1) as
/// `\xNN`. Records are newline-framed (RFC 6587), and observation values
/// come off the wire (DNS names, HTTP hosts, …): a raw LF in one would end
/// the record and let the rest of the value forge another.
fn push_control_escaped(out: &mut String, s: &str) {
    for ch in s.chars() {
        push_char_escaped(out, ch);
    }
}

fn push_char_escaped(out: &mut String, ch: char) {
    use std::fmt::Write as _;
    if ch.is_control() {
        let _ = write!(out, "\\x{:02x}", ch as u32);
    } else {
        out.push(ch);
    }
}

impl<W: Write + Send> AnomalySink for SyslogSink<W> {
    fn write(&mut self, record: &AnomalyRecord<'_>) {
        render_rfc5424(
            &mut self.scratch,
            self.facility,
            &self.app_name,
            &self.hostname,
            &self.procid,
            &self.enterprise_id,
            record,
        );
        // One write per line. Swallow errors like the other shipped sinks
        // (a broken syslog stream is operator-recoverable, not a panic).
        let _ = writeln!(self.writer, "{}", self.scratch);
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts_fixed() -> Timestamp {
        // 2026-06-07T00:00:00.000000Z
        Timestamp::from_unix_f64(1_780_790_400.0)
    }

    fn render(
        sev: Severity,
        kind: &'static str,
        obs: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) -> String {
        let mut out = String::new();
        render_rfc5424(
            &mut out,
            SyslogFacility::Local0,
            "netring",
            "host1",
            "-",
            "32473",
            &AnomalyRecord::new(kind, sev, ts_fixed())
                .with_observations(obs)
                .with_metrics(metrics),
        );
        out
    }

    #[test]
    fn pri_is_facility_times_8_plus_severity() {
        // local0 (16) * 8 = 128; +severity. Warning = 4 → 132.
        let line = render(Severity::Warning, "port_scan", &[], &[]);
        assert!(line.starts_with("<132>1 "), "line = {line}");
        // Critical = 2 → 130.
        let crit = render(Severity::Critical, "exfil", &[], &[]);
        assert!(crit.starts_with("<130>1 "), "crit = {crit}");
    }

    #[test]
    fn header_fields_and_no_sd_render_as_nilvalue() {
        let line = render(Severity::Info, "heartbeat", &[], &[]);
        // <PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID SD MSG
        assert_eq!(
            line,
            "<134>1 2026-06-07T00:00:00.000000Z host1 netring - heartbeat - heartbeat"
        );
    }

    /// RFC 5424 §6.2.3: TIME-SECFRAC is at most 6 digits (its example 5,
    /// with 9, is invalid) — microseconds, truncated.
    #[test]
    fn timestamp_has_at_most_six_fractional_digits() {
        let mut out = String::new();
        render_rfc5424(
            &mut out,
            SyslogFacility::Local0,
            "netring",
            "-",
            "-",
            "32473",
            &AnomalyRecord::new(
                "k",
                Severity::Info,
                Timestamp::new(1_780_790_400, 123_456_789),
            ),
        );
        assert!(
            out.starts_with("<134>1 2026-06-07T00:00:00.123456Z - "),
            "{out}"
        );
    }

    #[test]
    fn structured_data_carries_observations_and_metrics() {
        let line = render(
            Severity::Error,
            "dns_burst",
            &[("src", Cow::Borrowed("10.0.0.5"))],
            &[("qps", 142.0)],
        );
        // SD element present with both params; MSG echoes the observation.
        assert!(
            line.contains("[netring@32473 src=\"10.0.0.5\" qps=\"142\"]"),
            "line = {line}"
        );
        assert!(line.ends_with(" dns_burst src=10.0.0.5"), "line = {line}");
    }

    /// #215: the endpoints are SD params, the initiator as `src`.
    #[test]
    fn structured_data_carries_the_endpoints() {
        use crate::anomaly::sink::Endpoints;
        let key = flowscope::extract::FiveTupleKey::new(
            flowscope::L4Proto::Tcp,
            "[2001:db8::1]:80".parse().unwrap(),
            "[2001:db8::9]:40000".parse().unwrap(),
        );
        let mut out = String::new();
        render_rfc5424(
            &mut out,
            SyslogFacility::Local0,
            "netring",
            "-",
            "-",
            "32473",
            &AnomalyRecord::new("k", Severity::Info, ts_fixed())
                .with_endpoints(Endpoints::from_flow(&key, flowscope::Orientation::Reverse))
                .with_key(&key),
        );
        assert!(
            out.contains(
                r#"[netring@32473 src="[2001:db8::9]:40000" dst="[2001:db8::1]:80" proto="TCP"]"#
            ),
            "{out}"
        );
    }

    #[test]
    fn sd_param_values_are_escaped() {
        let mut out = String::new();
        push_sd_escaped(&mut out, r#"a"b\c]d"#);
        assert_eq!(out, r#"a\"b\\c\]d"#);
    }

    /// Observation values come off the wire (DNS names, HTTP hosts, …):
    /// a control character in one must not end the record and start a
    /// forged one, in the SD params or in the MSG.
    #[test]
    fn control_characters_cannot_forge_a_record() {
        let mut sink = SyslogSink::new(Vec::<u8>::new());
        sink.write(
            &AnomalyRecord::new("dga", Severity::Warning, ts_fixed())
                .with_observations(&[("qname", Cow::Borrowed("x\n<34>1 forged\r\0\u{85}é"))]),
        );
        let out = String::from_utf8(sink.into_inner()).unwrap();
        let line = out.strip_suffix('\n').expect("LF-framed");
        assert!(!line.contains(char::is_control), "{out:?}");
        assert!(
            line.contains(r#"qname="x\x0a<34>1 forged\x0d\x00\x85é""#),
            "{line}"
        );
        assert!(
            line.ends_with(r" dga qname=x\x0a<34>1 forged\x0d\x00\x85é"),
            "{line}"
        );
    }

    #[test]
    fn sink_writes_one_line_per_anomaly() {
        let mut sink = SyslogSink::new(Vec::<u8>::new()).hostname("h");
        sink.write(&AnomalyRecord::new("k1", Severity::Info, ts_fixed()));
        sink.write(&AnomalyRecord::new("k2", Severity::Warning, ts_fixed()));
        let out = String::from_utf8(sink.into_inner()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains(" k1 "));
        assert!(lines[1].starts_with("<132>1 ")); // warning
    }
}
