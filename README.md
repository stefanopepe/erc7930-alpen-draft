# erc7930-alpen

Encode and decode [ERC-7930](https://ercs.ethereum.org/ERCS/erc-7930) **interoperable addresses** for the [Alpen](https://alpenlabs.io) chain, following the [CAIP-350](https://chainagnostic.org/CAIPs/caip-350) binary serialization standard.

| Script | Direction |
|--------|-----------|
| `alpen_to_caip350.py` | EVM address **&rarr;** ERC-7930 envelope |
| `alpen_from_caip350.py` | ERC-7930 envelope **&rarr;** EVM address |

## Why?

Different blockchains use different address formats. ERC-7930 defines a single binary envelope that wraps any blockchain address together with its chain identity, so wallets, bridges, and dApps can pass addresses around without ambiguity.

These scripts produce and parse that envelope for Alpen, an EVM-compatible chain.

## Namespaces

Alpen addresses can be encoded under two CAIP-2 namespaces:

| Namespace | ChainType | Chain reference | When to use |
|-----------|-----------|-----------------|-------------|
| `eip155` | `0x0000` | Numeric chain ID (big-endian, min bytes) | Standard EVM interop — identifies Alpen by its EIP-155 chain ID |
| `strata` | `0xFFFF`\* | 32-byte genesis block hash (keccak256) | Fork-aware identification — binds to a specific chain genesis |

\* `0xFFFF` is a placeholder until CASA assigns an official ChainType value.

### Alpen chain identities

**eip155:**

| Network | Chain ID | Chain Ref (hex) | CAIP-2 |
|---------|----------|-----------------|--------|
| Testnet | 8150     | `0x1fd6`        | `eip155:8150` |
| Mainnet | 815      | `0x032f`        | `eip155:815` |

**strata:**

| Network | Genesis Hash | CAIP-2 |
|---------|-------------|--------|
| Testnet | `0x0102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a` | `strata:0102272379ba01273f82eb5ad1b00d26` |

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
- **AddrLen** `0x14` — 20 bytes for standard EVM addresses.
- **Address** — the raw address bytes.

**eip155 example** — Alpen testnet (chain 8150):

```
0x 0001 0000 02 1fd6 14 d8da6bf26964af9d7eed9e03e53415d37aa96045
   ──── ──── ── ──── ── ────────────────────────────────────────────
   ver  type len ref  len address (20 bytes)
```

**strata example** — Alpen testnet (genesis hash):

```
0x 0001 ffff 20 0102272379ba01273f82eb5ad1b00d26...c9d3447a 14 5400...0011
   ──── ──── ── ──────────────────────────────────── ── ──────────
   ver  type len chain ref (32 bytes genesis hash)   len address
```

## Quick start

Python 3.7+, no dependencies.

### Encode (EVM address &rarr; ERC-7930)

```bash
# eip155 — Alpen coinbase on testnet (defaults)
python3 alpen_to_caip350.py

# eip155 — specific address on mainnet
python3 alpen_to_caip350.py --address 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --chain-id 815

# strata — Alpen coinbase with testnet genesis (defaults)
python3 alpen_to_caip350.py --namespace strata

# strata — specific address with custom genesis hash
python3 alpen_to_caip350.py --namespace strata --address 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --genesis-hash 0x...

# Run all test vectors
python3 alpen_to_caip350.py --test
```

### Decode (ERC-7930 &rarr; EVM address)

The decoder auto-detects the namespace from the ChainType field.

```bash
# Decode an eip155 envelope
python3 alpen_from_caip350.py --erc7930 0x00010000021fd6145400000000000000000000000000000000000011

# Decode a strata envelope
python3 alpen_from_caip350.py --erc7930 0x0001ffff200102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a145400000000000000000000000000000000000011

# Strict mode — reject non-Alpen chain identities
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

**strata** — using Alpen testnet genesis + coinbase address:

| Description | ERC-7930 (hex) |
|-------------|---------------|
| Alpen testnet, coinbase | `0x0001ffff200102272379ba01273f82eb5ad1b00d2616458ad308efdfe4a6cc3012c9d3447a145400000000000000000000000000000000000011` |

## Relevant specs

- [ERC-7930 — Interoperable Addresses](https://ercs.ethereum.org/ERCS/erc-7930)
- [CAIP-350 — Binary Serialization of Blockchain IDs and Addresses](https://chainagnostic.org/CAIPs/caip-350)
- [CAIP-2 — Blockchain ID Specification](https://chainagnostic.org/CAIPs/caip-2)
- [CAIP-10 — Account ID Specification](https://chainagnostic.org/CAIPs/caip-10)
- [eip155 CAIP-350 Profile](https://namespaces.chainagnostic.org/eip155/caip350)

## License

MIT
