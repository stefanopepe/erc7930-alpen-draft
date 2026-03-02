#!/usr/bin/env python3
"""
Encoder: Alpen EVM Address → CAIP-350 / ERC-7930 Interoperable Address

Encodes a standard 0x EVM address into the ERC-7930 binary format.
Supports two namespaces:
  - eip155  (ChainType 0x0000) — chain ref = numeric chain ID
  - strata  (ChainType 0xFFFF) — chain ref = 32-byte genesis block hash

See alpen_from_caip350.py for the decoder.

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
EVM_ADDRESS_LENGTH = 20  # bytes
STARKNET_ADDRESS_LENGTH = 32  # bytes (felt252)
GENESIS_HASH_LENGTH = 32  # bytes

ALPEN_TESTNET_CHAIN_ID = 8150
ALPEN_MAINNET_CHAIN_ID = 815
ALPEN_COINBASE = "0x5400000000000000000000000000000000000011"  # standard Alpen coinbase
ALPEN_TESTNET_GENESIS = "0x0102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a"
STARKNET_GENESIS = "0x03237338cdabf1a819d469f497dcf4ee879a1eb4c5602a1fd84d78bcde090d33"
STARKNET_SAMPLE_ADDRESS = "0x04505a9f06f2bd639b6601f37a4dc0908bb70e8e0e0c34b1220827d64f4fc066"


# ── Core functions ───────────────────────────────────────────────────────────

def chain_id_to_ref_bytes(chain_id: int) -> bytes:
    """Convert a chain ID to big-endian bytes, minimum length, no leading zeros.

    Per the eip155 CAIP-350 profile the chain reference binary form is the
    chain ID encoded as a big-endian unsigned integer using the minimum number
    of bytes necessary (no leading zero bytes).

    Examples:
        1        -> 0x01
        10       -> 0x0a
        815      -> 0x032f
        8150     -> 0x1fd6
        11155111 -> 0xaa36a7
    """
    if chain_id <= 0:
        raise ValueError(f"chain_id must be a positive integer, got {chain_id}")
    byte_length = (chain_id.bit_length() + 7) // 8
    return chain_id.to_bytes(byte_length, byteorder="big")


def validate_address(address: str, expected_length: int = EVM_ADDRESS_LENGTH) -> bytes:
    """Parse a 0x-prefixed hex address and return raw bytes.

    Args:
        address: 0x-prefixed hex string.
        expected_length: Expected byte length (20 for EVM, 32 for Starknet).
    """
    if not address.startswith("0x") and not address.startswith("0X"):
        raise ValueError(f"Address must start with 0x, got: {address[:6]}...")
    hex_part = address[2:]
    if len(hex_part) != expected_length * 2:
        raise ValueError(
            f"Address must be {expected_length * 2} hex chars, got {len(hex_part)}"
        )
    try:
        return bytes.fromhex(hex_part)
    except ValueError:
        raise ValueError(f"Address contains invalid hex characters: {address}")


def validate_genesis_hash(genesis: str) -> bytes:
    """Parse a 0x-prefixed 64-hex-char genesis block hash and return raw 32 bytes."""
    if not genesis.startswith("0x") and not genesis.startswith("0X"):
        raise ValueError(f"Genesis hash must start with 0x, got: {genesis[:6]}...")
    hex_part = genesis[2:]
    if len(hex_part) != GENESIS_HASH_LENGTH * 2:
        raise ValueError(
            f"Genesis hash must be {GENESIS_HASH_LENGTH * 2} hex chars, got {len(hex_part)}"
        )
    try:
        return bytes.fromhex(hex_part)
    except ValueError:
        raise ValueError(f"Genesis hash contains invalid hex characters: {genesis}")


def encode_erc7930(address_bytes: bytes, *, namespace: str = "eip155",
                   chain_id: int = 0, genesis_hash_bytes: bytes = b"") -> bytes:
    """Assemble a full ERC-7930 interoperable address envelope.

    For eip155:  pass chain_id (int).
    For strata:  pass genesis_hash_bytes (32 bytes).
    """
    if namespace == "eip155":
        chain_type = EIP155_CHAIN_TYPE
        chain_ref = chain_id_to_ref_bytes(chain_id)
    elif namespace == "strata":
        chain_type = STRATA_CHAIN_TYPE
        chain_ref = genesis_hash_bytes
    else:
        raise ValueError(f"Unsupported namespace: {namespace}")

    header = struct.pack(">HH", ERC7930_VERSION, chain_type)
    chain_part = struct.pack("B", len(chain_ref)) + chain_ref
    addr_part = struct.pack("B", len(address_bytes)) + address_bytes

    return header + chain_part + addr_part


# ── Formatting helpers ───────────────────────────────────────────────────────

def format_caip2(chain_id: int) -> str:
    """CAIP-2 chain identifier for eip155, e.g. 'eip155:8150'."""
    return f"eip155:{chain_id}"


def format_caip10(chain_id: int, address: str) -> str:
    """CAIP-10 account identifier for eip155, e.g. 'eip155:8150:0xd8dA...'."""
    return f"eip155:{chain_id}:{address}"


def format_caip2_strata(genesis_hash_hex: str) -> str:
    """CAIP-2 chain identifier for strata.

    Uses the first 32 hex chars (16 bytes) of the genesis hash to fit
    the CAIP-2 reference length limit of 32 characters.
    """
    ref = genesis_hash_hex.lower().removeprefix("0x")[:32]
    return f"strata:{ref}"


def format_caip10_strata(genesis_hash_hex: str, address: str) -> str:
    """CAIP-10 account identifier for strata."""
    ref = genesis_hash_hex.lower().removeprefix("0x")[:32]
    return f"strata:{ref}:{address}"


def pretty_breakdown(address_bytes: bytes, *, namespace: str = "eip155",
                     chain_id: int = 0, genesis_hash_bytes: bytes = b"") -> str:
    """Return a human-readable field-by-field breakdown of the ERC-7930 encoding."""
    if namespace == "eip155":
        chain_type = EIP155_CHAIN_TYPE
        chain_ref = chain_id_to_ref_bytes(chain_id)
        ref_label = f"chain ID {chain_id}"
        ns_label = "eip155"
    else:
        chain_type = STRATA_CHAIN_TYPE
        chain_ref = genesis_hash_bytes
        ref_label = "genesis hash"
        ns_label = "strata"

    lines = [
        f"  Version          : 0x{ERC7930_VERSION:04x}",
        f"  ChainType        : 0x{chain_type:04x}  ({ns_label})",
        f"  ChainRefLength   : 0x{len(chain_ref):02x}  ({len(chain_ref)} byte{'s' if len(chain_ref) != 1 else ''})",
        f"  ChainReference   : 0x{chain_ref.hex()}  ({ref_label})",
        f"  AddressLength    : 0x{len(address_bytes):02x}  ({len(address_bytes)} bytes)",
        f"  Address          : 0x{address_bytes.hex()}",
    ]
    return "\n".join(lines)


# ── Test vectors ─────────────────────────────────────────────────────────────

# eip155 vectors: (description, chain_id, address_hex, expected_erc7930_hex)
SPEC_TEST_VECTORS = [
    (
        "ERC-7930 spec — Ethereum mainnet (vitalik.eth)",
        1,
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "00010000010114d8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
]

ALPEN_EIP155_VECTORS = [
    (
        "Alpen testnet eip155 (chain 8150)",
        ALPEN_TESTNET_CHAIN_ID,
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "00010000021fd614d8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
    (
        "Alpen mainnet eip155 (chain 815)",
        ALPEN_MAINNET_CHAIN_ID,
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "0001000002032f14d8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
]

# strata vectors: (description, genesis_hash_hex, address_hex, addr_length, expected_erc7930_hex)
STRATA_VECTORS = [
    (
        "Alpen testnet strata — coinbase (20B addr)",
        ALPEN_TESTNET_GENESIS,
        ALPEN_COINBASE,
        EVM_ADDRESS_LENGTH,
        "0001ffff200102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a145400000000000000000000000000000000000011",
    ),
    (
        "Alpen testnet strata — vitalik (20B addr)",
        ALPEN_TESTNET_GENESIS,
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        EVM_ADDRESS_LENGTH,
        "0001ffff200102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a14d8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
    (
        "Starknet strata (32B addr)",
        STARKNET_GENESIS,
        STARKNET_SAMPLE_ADDRESS,
        STARKNET_ADDRESS_LENGTH,
        "0001ffff2003237338cdabf1a819d469f497dcf4ee879a1eb4c5602a1fd84d78bcde090d332004505a9f06f2bd639b6601f37a4dc0908bb70e8e0e0c34b1220827d64f4fc066",
    ),
]


def run_tests() -> bool:
    """Run built-in test vectors. Returns True if all pass."""
    all_pass = True

    # eip155 encode tests
    print("eip155 encode tests:")
    for desc, chain_id, addr_hex, expected_hex in SPEC_TEST_VECTORS + ALPEN_EIP155_VECTORS:
        expected = expected_hex.replace(" ", "").lower()
        addr_bytes = validate_address(addr_hex)
        result = encode_erc7930(addr_bytes, namespace="eip155", chain_id=chain_id).hex()

        ok = result == expected
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {desc}")
        if not ok:
            print(f"         expected: 0x{expected}")
            print(f"         got:      0x{result}")
            all_pass = False
        else:
            print(f"         0x{result}")

    # chain reference byte checks
    print("\nChain reference byte encoding:")
    for cid, expected in [(1, "01"), (10, "0a"), (815, "032f"), (8150, "1fd6"), (11155111, "aa36a7")]:
        ref = chain_id_to_ref_bytes(cid).hex()
        ok = ref == expected
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] chain {cid:>10} -> 0x{ref}  (expected 0x{expected})")
        if not ok:
            all_pass = False

    # strata encode tests
    print("\nstrata encode tests:")
    for desc, genesis_hex, addr_hex, addr_len, expected_hex in STRATA_VECTORS:
        expected = expected_hex.replace(" ", "").lower()
        addr_bytes = validate_address(addr_hex, expected_length=addr_len)
        genesis_bytes = validate_genesis_hash(genesis_hex)
        result = encode_erc7930(addr_bytes, namespace="strata", genesis_hash_bytes=genesis_bytes).hex()

        ok = result == expected
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {desc}")
        if not ok:
            print(f"         expected: 0x{expected}")
            print(f"         got:      0x{result}")
            all_pass = False
        else:
            print(f"         0x{result}")

    return all_pass


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Encode an EVM address as a CAIP-350 / ERC-7930 interoperable address."
    )
    parser.add_argument(
        "--namespace",
        choices=["eip155", "strata"],
        default="eip155",
        help="CAIP-2 namespace (default: eip155)",
    )
    parser.add_argument(
        "--address",
        type=str,
        help="Address (0x-prefixed; 40 hex for EVM, 64 hex for Starknet; default: Alpen coinbase)",
    )
    parser.add_argument(
        "--address-length",
        type=int,
        default=None,
        help="Address byte length — strata only (default: auto-detect from --address)",
    )
    parser.add_argument(
        "--chain-id",
        type=int,
        default=ALPEN_TESTNET_CHAIN_ID,
        help=f"EIP-155 chain ID — eip155 only (default: {ALPEN_TESTNET_CHAIN_ID})",
    )
    parser.add_argument(
        "--genesis-hash",
        type=str,
        default=ALPEN_TESTNET_GENESIS,
        help="Genesis block hash (0x, 64 hex chars) — strata only (default: Alpen testnet)",
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

    if not args.address:
        args.address = ALPEN_COINBASE

    # Determine expected address length
    if args.address_length is not None:
        addr_len = args.address_length
    else:
        # Auto-detect from hex length
        hex_len = len(args.address.removeprefix("0x").removeprefix("0X"))
        addr_len = hex_len // 2

    address_bytes = validate_address(args.address, expected_length=addr_len)

    if args.namespace == "eip155":
        erc7930 = encode_erc7930(address_bytes, namespace="eip155", chain_id=args.chain_id)
        print(f"CAIP-2  : {format_caip2(args.chain_id)}")
        print(f"CAIP-10 : {format_caip10(args.chain_id, args.address)}")
        print(f"Chain reference bytes : 0x{chain_id_to_ref_bytes(args.chain_id).hex()}")
        print(f"ERC-7930 (hex)        : 0x{erc7930.hex()}")
        print()
        print("Field breakdown:")
        print(pretty_breakdown(address_bytes, namespace="eip155", chain_id=args.chain_id))
    else:
        genesis_bytes = validate_genesis_hash(args.genesis_hash)
        erc7930 = encode_erc7930(address_bytes, namespace="strata", genesis_hash_bytes=genesis_bytes)
        print(f"CAIP-2  : {format_caip2_strata(args.genesis_hash)}")
        print(f"CAIP-10 : {format_caip10_strata(args.genesis_hash, args.address)}")
        print(f"Genesis hash          : {args.genesis_hash}")
        print(f"ERC-7930 (hex)        : 0x{erc7930.hex()}")
        print()
        print("Field breakdown:")
        print(pretty_breakdown(address_bytes, namespace="strata", genesis_hash_bytes=genesis_bytes))


if __name__ == "__main__":
    main()
