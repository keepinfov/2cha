//! # Obfuscation profile
//!
//! Selects how v4 datagrams are framed on the wire. Two philosophies:
//!
//! - [`ObfsProfile::Quic`] — *mimicry*: every datagram is shaped to look like
//!   QUIC v1 (fixed version, CID-length markers, length varints). See [`wire`].
//! - [`ObfsProfile::Awg`] — AmneziaWG-2.0-style *randomization*: the only
//!   structured plaintext is a per-packet random "magic header" (a `u32` drawn
//!   from a configured, non-overlapping range per message class). There are no
//!   constant bytes on the wire; the receiver classifies a datagram by which
//!   header range its leading `u32` falls into. Junk and signature packets sent
//!   before the handshake live at the transport layer, not here.
//!
//! This module carries no RNG (per the crate's no-secrets-RNG rule): callers in
//! `twocha-core` pick a random header value inside the configured range and
//! hand it to the `wire` encoders, exactly as they supply QUIC throwaway CIDs.
//!
//! [`wire`]: crate::wire

/// The four message classes that carry an AmneziaWG magic header, indexing
/// [`AwgParams::headers`] / [`AwgParams::padding`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgClass {
    Init = 0,
    Resp = 1,
    Cookie = 2,
    Data = 3,
}

/// An inclusive `u32` range a magic header may take. In AmneziaWG 2.0 the four
/// ranges are dynamic (each packet picks a fresh value inside its range) and
/// must not overlap, so the leading `u32` unambiguously identifies the class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderRange {
    pub min: u32,
    pub max: u32,
}

impl HeaderRange {
    pub const fn new(min: u32, max: u32) -> Self {
        HeaderRange { min, max }
    }

    /// A degenerate range holding exactly one value (AmneziaWG 1.x behaviour).
    pub const fn single(v: u32) -> Self {
        HeaderRange { min: v, max: v }
    }

    #[inline]
    pub fn contains(&self, v: u32) -> bool {
        self.min <= v && v <= self.max
    }

    /// Do the closed intervals `self` and `other` share any value?
    pub fn overlaps(&self, other: &HeaderRange) -> bool {
        self.min <= other.max && other.min <= self.max
    }
}

/// AmneziaWG-style obfuscation parameters shared by both ends (except the junk
/// counts, which are client-only and live at the transport layer).
#[derive(Clone, Debug)]
pub struct AwgParams {
    /// H1–H4: magic-header ranges for Init / Resp / Cookie / Data.
    pub headers: [HeaderRange; 4],
    /// S1–S4: maximum extra padding (bytes) for Init / Resp / Cookie / Data.
    /// For Init/Resp/Cookie this is trailing wire padding; for Data it caps the
    /// random padding carried *inside* the AEAD (trailing bytes can't be told
    /// from ciphertext, so data padding must be inner).
    pub padding: [u16; 4],
}

impl AwgParams {
    /// The header range for a message class.
    #[inline]
    pub fn header(&self, class: MsgClass) -> HeaderRange {
        self.headers[class as usize]
    }

    /// The max padding for a message class.
    #[inline]
    pub fn pad_max(&self, class: MsgClass) -> usize {
        self.padding[class as usize] as usize
    }

    /// Classify a leading header value, or `None` if it matches no range.
    pub fn classify(&self, header: u32) -> Option<MsgClass> {
        const CLASSES: [MsgClass; 4] = [
            MsgClass::Init,
            MsgClass::Resp,
            MsgClass::Cookie,
            MsgClass::Data,
        ];
        CLASSES
            .into_iter()
            .find(|&c| self.headers[c as usize].contains(header))
    }

    /// True if any two header ranges overlap (config validation rejects this,
    /// since an overlap makes classification ambiguous).
    pub fn has_overlap(&self) -> bool {
        for i in 0..self.headers.len() {
            for j in (i + 1)..self.headers.len() {
                if self.headers[i].overlaps(&self.headers[j]) {
                    return true;
                }
            }
        }
        false
    }
}

/// Which on-wire obfuscation a session uses. `Quic` is the backwards-compatible
/// default; `Awg` carries the AmneziaWG magic-header/padding parameters.
#[derive(Clone, Debug, Default)]
pub enum ObfsProfile {
    #[default]
    Quic,
    Awg(AwgParams),
}

impl ObfsProfile {
    pub fn is_awg(&self) -> bool {
        matches!(self, ObfsProfile::Awg(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_contains_and_overlap() {
        let a = HeaderRange::new(10, 20);
        assert!(a.contains(10) && a.contains(20) && !a.contains(21));
        assert!(a.overlaps(&HeaderRange::new(20, 30)));
        assert!(!a.overlaps(&HeaderRange::new(21, 30)));
    }

    #[test]
    fn classify_and_overlap_detection() {
        let p = AwgParams {
            headers: [
                HeaderRange::new(100, 199),
                HeaderRange::new(200, 299),
                HeaderRange::new(300, 399),
                HeaderRange::new(400, 499),
            ],
            padding: [16, 16, 16, 16],
        };
        assert!(!p.has_overlap());
        assert_eq!(p.classify(150), Some(MsgClass::Init));
        assert_eq!(p.classify(450), Some(MsgClass::Data));
        assert_eq!(p.classify(50), None);

        let bad = AwgParams {
            headers: [
                HeaderRange::new(100, 250),
                HeaderRange::new(200, 299),
                HeaderRange::new(300, 399),
                HeaderRange::new(400, 499),
            ],
            padding: [0; 4],
        };
        assert!(bad.has_overlap());
    }
}
