#!/usr/bin/env python3
"""
Decoder: CAIP-350 / ERC-7930 Interoperable Address → Alpen EVM Address

Parses an ERC-7930 binary envelope and extracts the chain ID and plain
EVM address. See alpen_to_caip350.py for the encoder.

Binary layout (ERC-7930):
  Version (2B) | ChainType (2B) | ChainRefLen (1B) | ChainRef (var) | AddrLen (1B) | Address (var)
  0x0001       | 0x0000         | N                | BE(chainId)    | 0x14         | 20 raw bytes

No external dependencies — stdlib only.
"""

import argparse
import struct
import sys

# ── Constants ────────────────────────────────────────────────────────────────

ERC7930_VERSION = 0x0001
EIP155_CHAIN_TYPE = 0x0000

ALPEN_TESTNET_CHAIN_ID = 8150
ALPEN_MAINNET_CHAIN_ID = 815
ALPEN_CHAIN_IDS = {ALPEN_TESTNET_CHAIN_ID, ALPEN_MAINNET_CHAIN_ID}


# ── Core functions ───────────────────────────────────────────────────────────

def decode_erc7930(data: bytes) -> dict:
    """Decode an ERC-7930 interoperable address envelope.

    Args:
        data: Raw bytes of the full ERC-7930 envelope.

    Returns:
        Dictionary with keys:
            version    (int)  — envelope version
            chain_type (int)  — namespace identifier
            chain_id   (int)  — decoded chain ID
            address    (str)  — EVM address as 0x-prefixed lowercase hex
            caip2      (str)  — CAIP-2 chain identifier
            caip10     (str)  — CAIP-10 account identifier

    Raises:
        ValueError on malformed input.
    """
    if len(data) < 6:
        raise ValueError(
            f"Input too short: need at least 6 bytes (header + lengths), got {len(data)}"
        )

    offset = 0

    # Version (2B)
    version = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if version != ERC7930_VERSION:
        raise ValueError(
            f"Unsupported version: 0x{version:04x} (expected 0x{ERC7930_VERSION:04x})"
        )

    # ChainType (2B)
    chain_type = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if chain_type != EIP155_CHAIN_TYPE:
        raise ValueError(
            f"Unsupported chain type: 0x{chain_type:04x} (expected 0x{EIP155_CHAIN_TYPE:04x} for eip155)"
        )

    # ChainReferenceLength (1B)
    chain_ref_len = data[offset]
    offset += 1

    if offset + chain_ref_len > len(data):
        raise ValueError(
            f"Truncated: chain reference length is {chain_ref_len} but only "
            f"{len(data) - offset} bytes remain"
        )

    # ChainReference (var) — big-endian unsigned int
    chain_ref_bytes = data[offset : offset + chain_ref_len]
    offset += chain_ref_len
    chain_id = int.from_bytes(chain_ref_bytes, byteorder="big") if chain_ref_len > 0 else 0

    # AddressLength (1B)
    if offset >= len(data):
        raise ValueError("Truncated: missing address length byte")
    addr_len = data[offset]
    offset += 1

    if offset + addr_len > len(data):
        raise ValueError(
            f"Truncated: address length is {addr_len} but only "
            f"{len(data) - offset} bytes remain"
        )

    # Address (var)
    address_bytes = data[offset : offset + addr_len]
    offset += addr_len

    address_hex = "0x" + address_bytes.hex()

    return {
        "version": version,
        "chain_type": chain_type,
        "chain_id": chain_id,
        "address": address_hex,
        "caip2": f"eip155:{chain_id}",
        "caip10": f"eip155:{chain_id}:{address_hex}",
    }


def parse_hex_input(hex_str: str) -> bytes:
    """Accept a hex string with or without 0x prefix and return bytes."""
    cleaned = hex_str.strip()
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError(f"Invalid hex input: {hex_str}")


# ── Test vectors ─────────────────────────────────────────────────────────────

# (description, erc7930_hex, expected_chain_id, expected_address)
DECODE_TEST_VECTORS = [
    (
        "ERC-7930 spec — Ethereum mainnet (vitalik.eth)",
        "00010000010114d8da6bf26964af9d7eed9e03e53415d37aa96045",
        1,
        "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
    (
        "Alpen testnet (chain 8150)",
        "00010000021fd614d8da6bf26964af9d7eed9e03e53415d37aa96045",
        8150,
        "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
    (
        "Alpen mainnet (chain 815)",
        "0001000002032f14d8da6bf26964af9d7eed9e03e53415d37aa96045",
        815,
        "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
    (
        "Alpen testnet — coinbase address",
        "00010000021fd6145400000000000000000000000000000000000011",
        8150,
        "0x5400000000000000000000000000000000000011",
    ),
]

ERROR_TEST_VECTORS = [
    ("Too short", "000100"),
    ("Wrong version", "00020000010114d8da6bf26964af9d7eed9e03e53415d37aa96045"),
    ("Wrong chain type", "00010001010114d8da6bf26964af9d7eed9e03e53415d37aa96045"),
    ("Truncated chain ref", "000100000201"),
    ("Truncated address", "00010000010114d8da6bf26964af9d7e"),
]


def run_tests() -> bool:
    """Run built-in test vectors. Returns True if all pass."""
    all_pass = True

    print("Decode tests:")
    for desc, erc7930_hex, expected_cid, expected_addr in DECODE_TEST_VECTORS:
        data = bytes.fromhex(erc7930_hex)
        try:
            result = decode_erc7930(data)
            cid_ok = result["chain_id"] == expected_cid
            addr_ok = result["address"] == expected_addr
            ok = cid_ok and addr_ok
        except Exception as e:
            ok = False
            result = {"error": str(e)}

        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {desc}")
        if not ok:
            print(f"         expected chain_id={expected_cid}, address={expected_addr}")
            print(f"         got: {result}")
            all_pass = False
        else:
            print(f"         chain {result['chain_id']} -> {result['address']}")

    print("\nError handling tests:")
    for desc, bad_hex in ERROR_TEST_VECTORS:
        data = bytes.fromhex(bad_hex)
        try:
            decode_erc7930(data)
            print(f"  [FAIL] {desc} — expected error but decoded successfully")
            all_pass = False
        except ValueError as e:
            print(f"  [PASS] {desc} — {e}")

    return all_pass


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Decode a CAIP-350 / ERC-7930 interoperable address into an EVM address."
    )
    parser.add_argument(
        "--erc7930",
        type=str,
        help="ERC-7930 hex blob to decode (with or without 0x prefix)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Only accept Alpen chain IDs (8150, 815)",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run built-in test vectors and exit",
    )

    args = parser.parse_args()

    if args.test:
        ok = run_tests()
        sys.exit(0 if ok else 1)

    if not args.erc7930:
        parser.error("--erc7930 is required (or use --test)")

    data = parse_hex_input(args.erc7930)
    result = decode_erc7930(data)

    if args.strict and result["chain_id"] not in ALPEN_CHAIN_IDS:
        print(
            f"Error: chain ID {result['chain_id']} is not an Alpen chain "
            f"(expected {ALPEN_TESTNET_CHAIN_ID} or {ALPEN_MAINNET_CHAIN_ID})",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"CAIP-2  : {result['caip2']}")
    print(f"CAIP-10 : {result['caip10']}")
    print(f"Chain ID         : {result['chain_id']}")
    print(f"EVM address      : {result['address']}")
    print()
    print("Field breakdown:")
    print(f"  Version          : 0x{result['version']:04x}")
    print(f"  ChainType        : 0x{result['chain_type']:04x}  (eip155)")
    print(f"  Chain ID         : {result['chain_id']}")
    print(f"  Address          : {result['address']}")


if __name__ == "__main__":
    main()
