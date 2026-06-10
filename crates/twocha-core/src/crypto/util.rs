//! # Cryptographic Utilities
//!
//! Security utilities using proven implementations from RustCrypto ecosystem.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Constant-time comparison (prevents timing attacks)
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Secure memory zeroing using zeroize crate
///
/// Ensures memory is actually zeroed and not optimized away by the compiler.
#[inline(never)]
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare_equal() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        assert!(constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_different() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 6];
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_different_length() {
        let a = [1, 2, 3];
        let b = [1, 2, 3, 4];
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_secure_zero() {
        let mut data = [0xffu8; 32];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}
