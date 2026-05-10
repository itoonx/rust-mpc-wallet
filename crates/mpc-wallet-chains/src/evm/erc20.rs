//! ERC-20 ABI calldata helpers.
//!
//! Per [EIP-20](https://eips.ethereum.org/EIPS/eip-20):
//! - `transfer(address,uint256)` — selector `0xa9059cbb`
//! - `balanceOf(address) returns (uint256)` — selector `0x70a08231`
//! - `decimals() returns (uint8)` — selector `0x313ce567`
//! - `symbol() returns (string)` — selector `0x95d89b41`
//!
//! Both selectors are the first 4 bytes of `keccak256("<sig>")`.
//! ABI encoding pads each `address`/`uint256` arg to 32 bytes (left-padded).

use mpc_wallet_core::error::CoreError;

/// Selector for `transfer(address,uint256)`.
pub const SELECTOR_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// Selector for `balanceOf(address)`.
pub const SELECTOR_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

/// Selector for `decimals()`.
pub const SELECTOR_DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];

/// Encode `transfer(address recipient, uint256 amount)` calldata.
///
/// `recipient` is a 0x-prefixed 20-byte EVM address (any case).
/// `amount` is the token amount in **smallest unit** as a decimal string
/// (e.g. "1500000" for 1.5 USDC at 6 decimals).
pub fn encode_transfer(recipient: &str, amount_dec: &str) -> Result<Vec<u8>, CoreError> {
    let addr = parse_address(recipient)?;
    let amt = parse_u256_be(amount_dec)?;

    let mut out = Vec::with_capacity(4 + 32 + 32);
    out.extend_from_slice(&SELECTOR_TRANSFER);
    // address arg: left-pad to 32 bytes
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&addr);
    // uint256 arg: 32-byte big-endian
    out.extend_from_slice(&amt);
    Ok(out)
}

/// Encode `balanceOf(address)` calldata.
pub fn encode_balance_of(holder: &str) -> Result<Vec<u8>, CoreError> {
    let addr = parse_address(holder)?;
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&SELECTOR_BALANCE_OF);
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&addr);
    Ok(out)
}

/// Encode `decimals()` calldata (just the selector).
pub fn encode_decimals() -> Vec<u8> {
    SELECTOR_DECIMALS.to_vec()
}

/// Decode a 32-byte (or shorter, zero-padded high) big-endian uint256 result
/// into a decimal string. Used for `balanceOf` / `totalSupply` results that
/// might exceed `u128`.
pub fn decode_uint256_decimal(bytes: &[u8]) -> Result<String, CoreError> {
    use alloy::primitives::U256;
    if bytes.is_empty() {
        return Ok("0".into());
    }
    let slice = if bytes.len() > 32 {
        &bytes[bytes.len() - 32..]
    } else {
        bytes
    };
    Ok(U256::from_be_slice(slice).to_string())
}

fn parse_address(s: &str) -> Result<[u8; 20], CoreError> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex)
        .map_err(|e| CoreError::InvalidInput(format!("invalid address hex: {e}")))?;
    if bytes.len() != 20 {
        return Err(CoreError::InvalidInput(format!(
            "address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a decimal-string uint256 into 32-byte big-endian.
fn parse_u256_be(dec: &str) -> Result<[u8; 32], CoreError> {
    use alloy::primitives::U256;
    let v = U256::from_str_radix(dec, 10)
        .map_err(|e| CoreError::InvalidInput(format!("invalid uint256 '{dec}': {e}")))?;
    Ok(v.to_be_bytes::<32>())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vector captured via viem (`scripts/evm-erc20-ref-vector.mjs`):
    ///
    /// ```js
    /// import { encodeFunctionData, parseAbi } from 'viem';
    /// const abi = parseAbi(['function transfer(address,uint256)']);
    /// encodeFunctionData({
    ///     abi, functionName: 'transfer',
    ///     args: ['0xAf3C5fEB2da46D532b0e6A9d78000508681047E7', 1500000n],
    /// });
    /// // → 0xa9059cbb
    /// //   000000000000000000000000af3c5feb2da46d532b0e6a9d78000508681047e7
    /// //   000000000000000000000000000000000000000000000000000000000016e360
    /// ```
    #[test]
    fn transfer_matches_viem_reference() {
        let calldata =
            encode_transfer("0xAf3C5fEB2da46D532b0e6A9d78000508681047E7", "1500000").unwrap();
        let expected = "a9059cbb\
            000000000000000000000000af3c5feb2da46d532b0e6a9d78000508681047e7\
            000000000000000000000000000000000000000000000000000000000016e360";
        assert_eq!(hex::encode(&calldata), expected);
        assert_eq!(calldata.len(), 68);
    }

    #[test]
    fn balance_of_calldata_36_bytes() {
        let calldata = encode_balance_of("0xAf3C5fEB2da46D532b0e6A9d78000508681047E7").unwrap();
        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata[0..4], &SELECTOR_BALANCE_OF);
    }

    #[test]
    fn rejects_non_20_byte_address() {
        assert!(encode_transfer("0x1234", "100").is_err());
    }

    #[test]
    fn rejects_bad_decimal() {
        assert!(encode_transfer("0xAf3C5fEB2da46D532b0e6A9d78000508681047E7", "0x1f4").is_err());
    }

    #[test]
    fn handles_max_uint256() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let calldata = encode_transfer("0xAf3C5fEB2da46D532b0e6A9d78000508681047E7", max).unwrap();
        // Last 32 bytes = all 0xff
        assert_eq!(&calldata[36..68], &[0xff; 32]);
    }
}
