#!/usr/bin/env python3
"""
Alpen EVM Address → CAIP-350 / ERC-7930 Interoperable Address Encoder

Encodes a standard 0x EVM address into the ERC-7930 binary format
using the eip155 CAIP-350 profile.

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
EVM_ADDRESS_LENGTH = 20  # bytes

ALPEN_TESTNET_CHAIN_ID = 8150
ALPEN_MAINNET_CHAIN_ID = 815
ALPEN_COINBASE = "0x5400000000000000000000000000000000000011"  # standard Alpen coinbase


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
    # int.to_bytes with minimal length
    byte_length = (chain_id.bit_length() + 7) // 8
    return chain_id.to_bytes(byte_length, byteorder="big")


def validate_address(address: str) -> bytes:
    """Parse a 0x-prefixed EVM hex address and return raw 20 bytes."""
    if not address.startswith("0x") and not address.startswith("0X"):
        raise ValueError(f"Address must start with 0x, got: {address[:6]}...")
    hex_part = address[2:]
    if len(hex_part) != EVM_ADDRESS_LENGTH * 2:
        raise ValueError(
            f"Address must be {EVM_ADDRESS_LENGTH * 2} hex chars, got {len(hex_part)}"
        )
    try:
        return bytes.fromhex(hex_part)
    except ValueError:
        raise ValueError(f"Address contains invalid hex characters: {address}")


def encode_erc7930(chain_id: int, address_bytes: bytes) -> bytes:
    """Assemble a full ERC-7930 interoperable address envelope.

    Returns the raw binary (use .hex() for display).
    """
    chain_ref = chain_id_to_ref_bytes(chain_id)
    addr_len = len(address_bytes)

    # Version (2B, big-endian) + ChainType (2B, big-endian)
    header = struct.pack(">HH", ERC7930_VERSION, EIP155_CHAIN_TYPE)
    # ChainReferenceLength (1B) + ChainReference (var)
    chain_part = struct.pack("B", len(chain_ref)) + chain_ref
    # AddressLength (1B) + Address (var)
    addr_part = struct.pack("B", addr_len) + address_bytes

    return header + chain_part + addr_part


def format_caip2(chain_id: int) -> str:
    """CAIP-2 chain identifier, e.g. 'eip155:8150'."""
    return f"eip155:{chain_id}"


def format_caip10(chain_id: int, address: str) -> str:
    """CAIP-10 account identifier, e.g. 'eip155:8150:0xd8dA...'."""
    return f"eip155:{chain_id}:{address}"


def pretty_breakdown(chain_id: int, address_bytes: bytes) -> str:
    """Return a human-readable field-by-field breakdown of the ERC-7930 encoding."""
    chain_ref = chain_id_to_ref_bytes(chain_id)
    lines = [
        f"  Version          : 0x{ERC7930_VERSION:04x}",
        f"  ChainType        : 0x{EIP155_CHAIN_TYPE:04x}  (eip155)",
        f"  ChainRefLength   : 0x{len(chain_ref):02x}  ({len(chain_ref)} byte{'s' if len(chain_ref) != 1 else ''})",
        f"  ChainReference   : 0x{chain_ref.hex()}  (chain ID {chain_id})",
        f"  AddressLength    : 0x{len(address_bytes):02x}  ({len(address_bytes)} bytes)",
        f"  Address          : 0x{address_bytes.hex()}",
    ]
    return "\n".join(lines)


# ── Test vectors ─────────────────────────────────────────────────────────────

SPEC_TEST_VECTORS = [
    # (description, chain_id, address_hex, expected_erc7930_hex)
    (
        "ERC-7930 spec — Ethereum mainnet (vitalik.eth)",
        1,
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "00010000010114d8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
]

ALPEN_TEST_VECTORS = [
    (
        "Alpen testnet (chain 8150)",
        ALPEN_TESTNET_CHAIN_ID,
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "00010000021fd614d8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
    (
        "Alpen mainnet (chain 815)",
        ALPEN_MAINNET_CHAIN_ID,
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "0001000002032f14d8da6bf26964af9d7eed9e03e53415d37aa96045",
    ),
]


def run_tests() -> bool:
    """Run built-in test vectors. Returns True if all pass."""
    all_pass = True
    all_vectors = SPEC_TEST_VECTORS + ALPEN_TEST_VECTORS

    for desc, chain_id, addr_hex, expected_hex in all_vectors:
        # Normalise expected (strip spaces for readability)
        expected = expected_hex.replace(" ", "").lower()
        addr_bytes = validate_address(addr_hex)
        result = encode_erc7930(chain_id, addr_bytes).hex()

        ok = result == expected
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {desc}")
        if not ok:
            print(f"       expected: 0x{expected}")
            print(f"       got:      0x{result}")
            all_pass = False
        else:
            print(f"       0x{result}")

    # Also print chain reference byte checks
    print("\nChain reference byte encoding:")
    for cid, expected in [(1, "01"), (10, "0a"), (815, "032f"), (8150, "1fd6"), (11155111, "aa36a7")]:
        ref = chain_id_to_ref_bytes(cid).hex()
        ok = ref == expected
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] chain {cid:>10} -> 0x{ref}  (expected 0x{expected})")
        if not ok:
            all_pass = False

    return all_pass


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Encode an EVM address as a CAIP-350 / ERC-7930 interoperable address."
    )
    parser.add_argument(
        "--address",
        type=str,
        help=f"EVM address (0x-prefixed, 40 hex chars; default: Alpen coinbase)",
    )
    parser.add_argument(
        "--chain-id",
        type=int,
        default=ALPEN_TESTNET_CHAIN_ID,
        help=f"EIP-155 chain ID (default: {ALPEN_TESTNET_CHAIN_ID} Alpen testnet)",
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

    address_bytes = validate_address(args.address)
    erc7930 = encode_erc7930(args.chain_id, address_bytes)

    print(f"CAIP-2  : {format_caip2(args.chain_id)}")
    print(f"CAIP-10 : {format_caip10(args.chain_id, args.address)}")
    print(f"Chain reference bytes : 0x{chain_id_to_ref_bytes(args.chain_id).hex()}")
    print(f"ERC-7930 (hex)        : 0x{erc7930.hex()}")
    print()
    print("Field breakdown:")
    print(pretty_breakdown(args.chain_id, address_bytes))


if __name__ == "__main__":
    main()
