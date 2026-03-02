#!/usr/bin/env python3
"""
Decoder: CAIP-350 / ERC-7930 Interoperable Address → Alpen EVM Address

Parses an ERC-7930 binary envelope and extracts the chain identity and
plain EVM address. Supports two namespaces:
  - eip155  (ChainType 0x0000) — chain ref = numeric chain ID
  - strata  (ChainType 0xFFFF) — chain ref = 32-byte genesis block hash

See alpen_to_caip350.py for the encoder.

Binary layout (ERC-7930):
  Version (2B) | ChainType (2B) | ChainRefLen (1B) | ChainRef (var) | AddrLen (1B) | Address (var)

No external dependencies — stdlib only.
"""

import argparse
import struct
import sys

# ── Constants ────────────────────────────────────────────────────────────────

ERC7930_VERSION = 0x0001
EIP155_CHAIN_TYPE = 0x0000
STRATA_CHAIN_TYPE = 0xFFFF  # placeholder until CASA assigns an official value

ALPEN_TESTNET_CHAIN_ID = 8150
ALPEN_MAINNET_CHAIN_ID = 815
ALPEN_CHAIN_IDS = {ALPEN_TESTNET_CHAIN_ID, ALPEN_MAINNET_CHAIN_ID}
ALPEN_TESTNET_GENESIS = "0x0102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a"
STARKNET_GENESIS = "0x03237338cdabf1a819d469f497dcf4ee879a1eb4c5602a1fd84d78bcde090d33"
KNOWN_STRATA_GENESIS_HASHES = {ALPEN_TESTNET_GENESIS, STARKNET_GENESIS}

CHAIN_TYPE_NAMES = {
    EIP155_CHAIN_TYPE: "eip155",
    STRATA_CHAIN_TYPE: "strata",
}


# ── Core functions ───────────────────────────────────────────────────────────

def decode_erc7930(data: bytes) -> dict:
    """Decode an ERC-7930 interoperable address envelope.

    Args:
        data: Raw bytes of the full ERC-7930 envelope.

    Returns:
        Dictionary with keys:
            version      (int)  — envelope version
            chain_type   (int)  — namespace identifier
            namespace    (str)  — "eip155" or "strata"
            address      (str)  — EVM address as 0x-prefixed lowercase hex
            caip2        (str)  — CAIP-2 chain identifier
            caip10       (str)  — CAIP-10 account identifier

        For eip155:
            chain_id     (int)  — decoded chain ID

        For strata:
            genesis_hash (str)  — full genesis hash as 0x-prefixed hex

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
    if chain_type not in CHAIN_TYPE_NAMES:
        raise ValueError(
            f"Unsupported chain type: 0x{chain_type:04x} "
            f"(supported: {', '.join(f'0x{k:04x} ({v})' for k, v in CHAIN_TYPE_NAMES.items())})"
        )
    namespace = CHAIN_TYPE_NAMES[chain_type]

    # ChainReferenceLength (1B)
    chain_ref_len = data[offset]
    offset += 1

    if offset + chain_ref_len > len(data):
        raise ValueError(
            f"Truncated: chain reference length is {chain_ref_len} but only "
            f"{len(data) - offset} bytes remain"
        )

    # ChainReference (var)
    chain_ref_bytes = data[offset : offset + chain_ref_len]
    offset += chain_ref_len

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
    address_hex = "0x" + address_bytes.hex()

    # Build result based on namespace
    result = {
        "version": version,
        "chain_type": chain_type,
        "namespace": namespace,
        "address": address_hex,
    }

    if namespace == "eip155":
        chain_id = int.from_bytes(chain_ref_bytes, byteorder="big") if chain_ref_len > 0 else 0
        result["chain_id"] = chain_id
        result["caip2"] = f"eip155:{chain_id}"
        result["caip10"] = f"eip155:{chain_id}:{address_hex}"
    else:  # strata
        genesis_hash = "0x" + chain_ref_bytes.hex()
        result["genesis_hash"] = genesis_hash
        # CAIP-2 text reference: first 32 hex chars (16 bytes) of genesis hash
        ref_short = chain_ref_bytes.hex()[:32]
        result["caip2"] = f"strata:{ref_short}"
        result["caip10"] = f"strata:{ref_short}:{address_hex}"

    return result


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

# eip155: (description, erc7930_hex, expected_chain_id, expected_address)
EIP155_DECODE_VECTORS = [
    (
        "ERC-7930 spec — Ethereum mainnet (vitalik.eth)",
        "00010000010114d8da6bf26964af9d7eed9e03e53415d37aa96045",
        1,
        "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
    (
        "Alpen testnet eip155 (chain 8150)",
        "00010000021fd614d8da6bf26964af9d7eed9e03e53415d37aa96045",
        8150,
        "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
    (
        "Alpen mainnet eip155 (chain 815)",
        "0001000002032f14d8da6bf26964af9d7eed9e03e53415d37aa96045",
        815,
        "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
    (
        "Alpen testnet eip155 — coinbase",
        "00010000021fd6145400000000000000000000000000000000000011",
        8150,
        "0x5400000000000000000000000000000000000011",
    ),
]

# strata: (description, erc7930_hex, expected_genesis_hash, expected_address)
STRATA_DECODE_VECTORS = [
    (
        "Alpen testnet strata — coinbase",
        "0001ffff200102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a145400000000000000000000000000000000000011",
        "0x0102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a",
        "0x5400000000000000000000000000000000000011",
    ),
    (
        "Alpen testnet strata — vitalik address",
        "0001ffff200102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a14d8da6bf26964af9d7eed9e03e53415d37aa96045",
        "0x0102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a",
        "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
    (
        "Starknet strata (32B addr)",
        "0001ffff2003237338cdabf1a819d469f497dcf4ee879a1eb4c5602a1fd84d78bcde090d332004505a9f06f2bd639b6601f37a4dc0908bb70e8e0e0c34b1220827d64f4fc066",
        "0x03237338cdabf1a819d469f497dcf4ee879a1eb4c5602a1fd84d78bcde090d33",
        "0x04505a9f06f2bd639b6601f37a4dc0908bb70e8e0e0c34b1220827d64f4fc066",
    ),
]

ERROR_TEST_VECTORS = [
    ("Too short", "000100"),
    ("Wrong version", "00020000010114d8da6bf26964af9d7eed9e03e53415d37aa96045"),
    ("Unknown chain type 0x0099", "00010099010114d8da6bf26964af9d7eed9e03e53415d37aa96045"),
    ("Truncated chain ref", "000100000201"),
    ("Truncated address", "00010000010114d8da6bf26964af9d7e"),
]


def run_tests() -> bool:
    """Run built-in test vectors. Returns True if all pass."""
    all_pass = True

    # eip155 decode tests
    print("eip155 decode tests:")
    for desc, erc7930_hex, expected_cid, expected_addr in EIP155_DECODE_VECTORS:
        data = bytes.fromhex(erc7930_hex)
        try:
            result = decode_erc7930(data)
            cid_ok = result.get("chain_id") == expected_cid
            addr_ok = result["address"] == expected_addr
            ns_ok = result["namespace"] == "eip155"
            ok = cid_ok and addr_ok and ns_ok
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

    # strata decode tests
    print("\nstrata decode tests:")
    for desc, erc7930_hex, expected_genesis, expected_addr in STRATA_DECODE_VECTORS:
        data = bytes.fromhex(erc7930_hex)
        try:
            result = decode_erc7930(data)
            gen_ok = result.get("genesis_hash") == expected_genesis
            addr_ok = result["address"] == expected_addr
            ns_ok = result["namespace"] == "strata"
            ok = gen_ok and addr_ok and ns_ok
        except Exception as e:
            ok = False
            result = {"error": str(e)}

        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {desc}")
        if not ok:
            print(f"         expected genesis={expected_genesis}, address={expected_addr}")
            print(f"         got: {result}")
            all_pass = False
        else:
            print(f"         {result['caip2']} -> {result['address']}")

    # error handling tests
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
        help="Only accept known chain identities (Alpen eip155 or known strata genesis hashes)",
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

    if args.strict:
        if result["namespace"] == "eip155" and result["chain_id"] not in ALPEN_CHAIN_IDS:
            print(
                f"Error: chain ID {result['chain_id']} is not a known Alpen chain",
                file=sys.stderr,
            )
            sys.exit(1)
        if result["namespace"] == "strata" and result.get("genesis_hash") not in KNOWN_STRATA_GENESIS_HASHES:
            print(
                f"Error: genesis hash {result.get('genesis_hash')} is not a known strata chain",
                file=sys.stderr,
            )
            sys.exit(1)

    print(f"Namespace : {result['namespace']}")
    print(f"CAIP-2    : {result['caip2']}")
    print(f"CAIP-10   : {result['caip10']}")

    if result["namespace"] == "eip155":
        print(f"Chain ID         : {result['chain_id']}")
    else:
        print(f"Genesis hash     : {result['genesis_hash']}")

    print(f"EVM address      : {result['address']}")
    print()
    print("Field breakdown:")
    print(f"  Version          : 0x{result['version']:04x}")
    print(f"  ChainType        : 0x{result['chain_type']:04x}  ({result['namespace']})")
    if result["namespace"] == "eip155":
        print(f"  Chain ID         : {result['chain_id']}")
    else:
        print(f"  Genesis hash     : {result['genesis_hash']}")
    print(f"  Address          : {result['address']}")


if __name__ == "__main__":
    main()
