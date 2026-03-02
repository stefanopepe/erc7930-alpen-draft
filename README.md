# erc7930-alpen

Encode and decode [ERC-7930](https://ercs.ethereum.org/ERCS/erc-7930) **interoperable addresses** for [Alpen](https://alpenlabs.io) and [Starknet](https://starknet.io) chains, following the [CAIP-350](https://chainagnostic.org/CAIPs/caip-350) binary serialization standard.

| Script | Direction |
|--------|-----------|
| `alpen_to_caip350.py` | Address **&rarr;** ERC-7930 envelope |
| `alpen_from_caip350.py` | ERC-7930 envelope **&rarr;** Address |

## Why?

Different blockchains use different address formats. ERC-7930 defines a single binary envelope that wraps any blockchain address together with its chain identity, so wallets, bridges, and dApps can pass addresses around without ambiguity.

These scripts produce and parse that envelope for Alpen (EVM, 20-byte addresses) and Starknet (felt252, 32-byte addresses).

## Namespaces

Addresses can be encoded under two CAIP-2 namespaces:

| Namespace | ChainType | Chain reference | Address size | When to use |
|-----------|-----------|-----------------|-------------|-------------|
| `eip155` | `0x0000` | Numeric chain ID (big-endian, min bytes) | 20 B (EVM) | Standard EVM interop — identifies a chain by its EIP-155 chain ID |
| `strata` | `0xFFFF`\* | 32-byte genesis block hash (keccak256) | Variable | Fork-aware identification — binds to a specific chain genesis |

\* `0xFFFF` is a placeholder until CASA assigns an official ChainType value.

The `strata:` namespace supports chains with different address sizes — 20 bytes for EVM chains like Alpen, 32 bytes for Starknet.

### Chain identities

**eip155:**

| Network | Chain ID | Chain Ref (hex) | CAIP-2 |
|---------|----------|-----------------|--------|
| Alpen testnet | 8150 | `0x1fd6` | `eip155:8150` |
| Alpen mainnet | 815  | `0x032f` | `eip155:815` |

**strata:**

| Chain | Genesis Hash | Addr size | CAIP-2 |
|-------|-------------|-----------|--------|
| Alpen testnet | `0x0102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a` | 20 B | `strata:0102272379ba01273f82eb5ad1b00d26` |
| Starknet | `0x03237338cdabf1a819d469f497dcf4ee879a1eb4c5602a1fd84d78bcde090d33` | 32 B | `strata:03237338cdabf1a819d469f497dcf4ee` |

The CAIP-2 text reference for strata uses the first 32 hex characters (16 bytes) of the genesis hash, per the CAIP-2 reference length limit. The binary CAIP-350 form carries the full 32 bytes.

## How the binary envelope works

ERC-7930 lays out six fields back-to-back:

```
┌──────────┬───────────┬──────────────┬──────────────┬───────────┬─────────┐
│ Version  │ ChainType │ ChainRefLen  │ ChainRef     │ AddrLen   │ Address │
│ 2 bytes  │ 2 bytes   │ 1 byte       │ variable     │ 1 byte    │ variable│
└──────────┴───────────┴──────────────┴──────────────┴───────────┴─────────┘
```

- **Version** `0x0001` — current ERC-7930 spec version.
- **ChainType** — namespace identifier (`0x0000` = eip155, `0xFFFF` = strata).
- **ChainRefLen** — byte length of ChainRef.
- **ChainRef** — eip155: chain ID as big-endian uint (min bytes, no leading zeros). strata: full 32-byte genesis hash.
- **AddrLen** — address byte length (`0x14` = 20 for EVM, `0x20` = 32 for Starknet).
- **Address** — the raw address bytes.

**eip155 example** — Alpen testnet (chain 8150), 20-byte address:

```
0x 0001 0000 02 1fd6 14 d8da6bf26964af9d7eed9e03e53415d37aa96045
   ──── ──── ── ──── ── ────────────────────────────────────────────
   ver  type len ref  len address (20 bytes)
```

**strata example** — Starknet, 32-byte address:

```
0x 0001 ffff 20 03237338cdabf1a819d469f497dcf4ee...de090d33 20 04505a9f06f2bd63...4f4fc066
   ──── ──── ── ──────────────────────────────────── ── ────────────────────────────────
   ver  type len chain ref (32B genesis hash)         len address (32 bytes)
```

## Quick start

Python 3.7+, no dependencies.

### Encode (address &rarr; ERC-7930)

```bash
# eip155 — Alpen coinbase on testnet (defaults)
python3 alpen_to_caip350.py

# eip155 — specific address on mainnet
python3 alpen_to_caip350.py --address 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --chain-id 815

# strata — Alpen coinbase with testnet genesis (defaults)
python3 alpen_to_caip350.py --namespace strata

# strata — Starknet address
python3 alpen_to_caip350.py --namespace strata \
  --genesis-hash 0x03237338cdabf1a819d469f497dcf4ee879a1eb4c5602a1fd84d78bcde090d33 \
  --address 0x04505a9f06f2bd639b6601f37a4dc0908bb70e8e0e0c34b1220827d64f4fc066

# Run all test vectors
python3 alpen_to_caip350.py --test
```

### Decode (ERC-7930 &rarr; address)

The decoder auto-detects the namespace from the ChainType field and handles both 20-byte and 32-byte addresses.

```bash
# Decode an eip155 envelope
python3 alpen_from_caip350.py --erc7930 0x00010000021fd6145400000000000000000000000000000000000011

# Decode a strata envelope (Alpen)
python3 alpen_from_caip350.py --erc7930 0x0001ffff200102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a145400000000000000000000000000000000000011

# Decode a strata envelope (Starknet, 32B address)
python3 alpen_from_caip350.py --erc7930 0x0001ffff2003237338cdabf1a819d469f497dcf4ee879a1eb4c5602a1fd84d78bcde090d332004505a9f06f2bd639b6601f37a4dc0908bb70e8e0e0c34b1220827d64f4fc066

# Strict mode — reject unknown chain identities
python3 alpen_from_caip350.py --erc7930 0x00010000010114d8da6bf26964af9d7eed9e03e53415d37aa96045 --strict

# Run all test vectors
python3 alpen_from_caip350.py --test
```

## Golden test vectors

### Chain reference encoding (eip155)

| Chain ID | Big-endian hex |
|----------|---------------|
| 1        | `0x01`        |
| 10       | `0x0a`        |
| 815      | `0x032f`      |
| 8150     | `0x1fd6`      |
| 11155111 | `0xaa36a7`    |

### Full ERC-7930 envelopes

**eip155** — using address `0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045`:

| Chain              | ERC-7930 (hex)                                                  |
|--------------------|-----------------------------------------------------------------|
| Ethereum mainnet   | `0x00010000010114d8da6bf26964af9d7eed9e03e53415d37aa96045`      |
| Alpen testnet 8150 | `0x00010000021fd614d8da6bf26964af9d7eed9e03e53415d37aa96045`    |
| Alpen mainnet 815  | `0x0001000002032f14d8da6bf26964af9d7eed9e03e53415d37aa96045`    |

The Ethereum mainnet vector is taken directly from the ERC-7930 spec as a cross-check.

**strata:**

| Chain | Address | ERC-7930 (hex) |
|-------|---------|---------------|
| Alpen testnet (20B) | `0x5400...0011` | `0x0001ffff200102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a145400000000000000000000000000000000000011` |
| Starknet (32B) | `0x0450...c066` | `0x0001ffff2003237338cdabf1a819d469f497dcf4ee879a1eb4c5602a1fd84d78bcde090d332004505a9f06f2bd639b6601f37a4dc0908bb70e8e0e0c34b1220827d64f4fc066` |

## Relevant specs

- [ERC-7930 — Interoperable Addresses](https://ercs.ethereum.org/ERCS/erc-7930)
- [CAIP-350 — Binary Serialization of Blockchain IDs and Addresses](https://chainagnostic.org/CAIPs/caip-350)
- [CAIP-2 — Blockchain ID Specification](https://chainagnostic.org/CAIPs/caip-2)
- [CAIP-10 — Account ID Specification](https://chainagnostic.org/CAIPs/caip-10)
- [eip155 CAIP-350 Profile](https://namespaces.chainagnostic.org/eip155/caip350)

## License

MIT
