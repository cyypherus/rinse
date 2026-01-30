pub(crate) const HDLC_FLAG: u8 = 0x7E;
pub(crate) const HDLC_ESC: u8 = 0x7D;
pub(crate) const HDLC_ESC_MASK: u8 = 0x20;

pub(crate) fn hdlc_escape(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len() * 2);
    for &byte in data {
        if byte == HDLC_ESC || byte == HDLC_FLAG {
            result.push(HDLC_ESC);
            result.push(byte ^ HDLC_ESC_MASK);
        } else {
            result.push(byte);
        }
    }
    result
}

pub(crate) fn hdlc_unescape(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut escape = false;
    for &byte in data {
        if escape {
            result.push(byte ^ HDLC_ESC_MASK);
            escape = false;
        } else if byte == HDLC_ESC {
            escape = true;
        } else {
            result.push(byte);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdlc_roundtrip() {
        let data = vec![0x00, 0x7E, 0x7D, 0xFF, 0x01];
        let escaped = hdlc_escape(&data);
        let unescaped = hdlc_unescape(&escaped);
        assert_eq!(data, unescaped);
    }

    #[test]
    fn hdlc_escape_flag() {
        let data = vec![HDLC_FLAG];
        let escaped = hdlc_escape(&data);
        assert_eq!(escaped, vec![HDLC_ESC, HDLC_FLAG ^ HDLC_ESC_MASK]);
    }

    #[test]
    fn hdlc_escape_esc() {
        let data = vec![HDLC_ESC];
        let escaped = hdlc_escape(&data);
        assert_eq!(escaped, vec![HDLC_ESC, HDLC_ESC ^ HDLC_ESC_MASK]);
    }
}
