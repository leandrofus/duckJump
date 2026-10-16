use hmac::{Hmac, Mac, KeyInit};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

const STEP_SECONDS: u64 = 30;
const DIGITS: u32 = 6;

/// Decodes an unpadded or padded base32 string into bytes.
pub fn decode_base32(s: &str) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for c in s.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let val = match c.to_ascii_uppercase() {
            'A'..='Z' => c.to_ascii_uppercase() as u8 - b'A',
            '2'..='7' => c as u8 - b'2' + 26,
            _ => anyhow::bail!("invalid base32 character: {}", c),
        };

        buffer = (buffer << 5) | (val as u64);
        bits_in_buffer += 5;

        while bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            out.push((buffer >> bits_in_buffer) as u8);
            buffer &= (1 << bits_in_buffer) - 1;
        }
    }

    Ok(out)
}

/// Computes the 6-digit TOTP code for a given base32 secret at the specified Unix timestamp.
pub fn compute_totp(secret_base32: &str, unix_timestamp: u64) -> anyhow::Result<String> {
    let key = decode_base32(secret_base32)?;
    let counter = unix_timestamp / STEP_SECONDS;
    let mut mac = HmacSha1::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("HMAC key initialization failed: {}", e))?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    let modulo = 10u32.pow(DIGITS);
    let code = binary % modulo;
    Ok(format!("{:06}", code))
}

/// Generates the current TOTP code and the seconds remaining until it rotates.
pub fn current_totp(secret_base32: &str) -> anyhow::Result<(String, u64)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs();
    let code = compute_totp(secret_base32, now)?;
    let remaining = STEP_SECONDS - (now % STEP_SECONDS);
    Ok((code, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_decode() {
        let decoded = decode_base32("MZXW6YTBOI").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "foobar");
    }

    #[test]
    fn test_totp_rfc6238_vector() {
        // "12345678901234567890" in base32 is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        // T = 59s -> step = 1
        assert_eq!(compute_totp(secret, 59).unwrap(), "287082");
        // T = 1111111109s
        assert_eq!(compute_totp(secret, 1111111109).unwrap(), "081804");
        // T = 1234567890s
        assert_eq!(compute_totp(secret, 1234567890).unwrap(), "005924");
    }
}
