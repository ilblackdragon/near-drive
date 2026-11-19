//! Tiny XML/encoding/date helpers. S3 request bodies we parse
//! (DeleteObjects, CompleteMultipartUpload) are flat enough that a small
//! tag scanner is sufficient; responses are built with `format!`.

pub fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c => o.push(c),
        }
    }
    o
}

pub fn unescape(s: &str) -> Option<String> {
    let mut o = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        o.push_str(&rest[..i]);
        let end = rest[i..].find(';')? + i;
        let ent = &rest[i + 1..end];
        match ent {
            "amp" => o.push('&'),
            "lt" => o.push('<'),
            "gt" => o.push('>'),
            "quot" => o.push('"'),
            "apos" => o.push('\''),
            _ => {
                let n = if let Some(h) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                    u32::from_str_radix(h, 16).ok()?
                } else {
                    ent.strip_prefix('#')?.parse().ok()?
                };
                o.push(char::from_u32(n)?);
            }
        }
        rest = &rest[end + 1..];
    }
    o.push_str(rest);
    Some(o)
}

/// Inner text of every `<tag>…</tag>` (also `<tag attr=…>`) in `s`, in order.
/// CDATA is not supported (S3 SDKs never send it).
pub fn elements<'a>(s: &'a str, tag: &str) -> Vec<&'a str> {
    let mut out = vec![];
    let close = format!("</{tag}>");
    let mut rest = s;
    while let Some(start) = find_open(rest, tag) {
        let after = &rest[start..];
        let Some(gt) = after.find('>') else { break };
        if after[..gt].ends_with('/') {
            out.push("");
            rest = &after[gt + 1..];
            continue;
        }
        let body = &after[gt + 1..];
        let Some(end) = body.find(&close) else { break };
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    out
}

fn find_open(s: &str, tag: &str) -> Option<usize> {
    let pat = format!("<{tag}");
    let mut from = 0;
    while let Some(i) = s[from..].find(&pat) {
        let i = from + i;
        match s.as_bytes().get(i + pat.len()) {
            Some(b'>') | Some(b' ') | Some(b'/') | Some(b'\t') | Some(b'\n') | Some(b'\r') => return Some(i),
            _ => from = i + pat.len(),
        }
    }
    None
}

/// First `<tag>` text, unescaped and trimmed.
pub fn text(s: &str, tag: &str) -> Option<String> {
    elements(s, tag).first().and_then(|t| unescape(t.trim()))
}

/// RFC 3986 encoding as SigV4 and `encoding-type=url` want it: everything but
/// unreserved characters is `%XX`; `/` is kept when `keep_slash`.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Percent-decode (`+` is left as is). Returns raw bytes.
pub fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn percent_decode_str(s: &str) -> Option<String> {
    String::from_utf8(percent_decode(s)).ok()
}

/// Days since 1970-01-01 → (year, month, day). (H. Hinnant's civil_from_days.)
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-11-19T10:00:00.000Z`
pub fn iso8601(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (y, mo, d) = civil(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", sod / 3600, sod / 60 % 60, sod % 60, ms % 1000)
}

pub fn http_date(ms: u64) -> String {
    httpdate::fmt_http_date(std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms / 1000 * 1000))
}

/// Parse SigV4 `YYYYMMDDTHHMMSSZ` to unix seconds.
pub fn parse_amz_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (n(0..4)?, n(4..6)?, n(6..8)?);
    let (h, mi, se) = (n(9..11)?, n(11..13)?, n(13..15)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(y, mo as u32, d as u32) * 86_400 + h * 3600 + mi * 60 + se)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_369_353_600_123), "2013-05-24T00:00:00.123Z");
        assert_eq!(parse_amz_date("20130524T000000Z"), Some(1_369_353_600));
        assert_eq!(parse_amz_date("20240229T235959Z"), Some(1_709_251_199));
        assert_eq!(http_date(1_369_353_600_999), "Fri, 24 May 2013 00:00:00 GMT");
    }

    #[test]
    fn xml_scan() {
        let x = "<Delete><Quiet>true</Quiet><Object><Key>a&amp;b</Key></Object><Object ><Key>c</Key><VersionId/></Object></Delete>";
        let objs = elements(x, "Object");
        assert_eq!(objs.len(), 2);
        assert_eq!(text(objs[0], "Key").unwrap(), "a&b");
        assert_eq!(text(x, "Quiet").unwrap(), "true");
        assert_eq!(unescape("&#x41;&#66;").unwrap(), "AB");
    }

    #[test]
    fn encoding() {
        assert_eq!(uri_encode("a b/c+d~", true), "a%20b/c%2Bd~");
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
        assert_eq!(percent_decode_str("a%20b%2fc%").unwrap(), "a b/c%");
    }
}
