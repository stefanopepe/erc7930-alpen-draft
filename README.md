# erc7930-alpen

Encode a standard EVM address (`0x...`) into an [ERC-7930](https://ercs.ethereum.org/ERCS/erc-7930) **interoperable address** for the [Alpen](https://alpenlabs.io) chain, following the [CAIP-350](https://chainagnostic.org/CAIPs/caip-350) binary serialization standard.

## Why?

Different blockchains use different address formats. ERC-7930 defines a single binary envelope that wraps any blockchain address together with its chain identity, so wallets, bridges, and dApps can pass addresses around without ambiguity.

This script produces that envelope for Alpen, an EVM-compatible chain.

## Alpen Chain IDs

| Network | Chain ID | Chain Ref (hex) |
|---------|----------|-----------------|
| Testnet | 8150     | `0x1fd6`        |
| Mainnet | 815      | `0x032f`        |

## How the binary envelope works

ERC-7930 lays out six fields back-to-back:

```
┌──────────┬───────────┬──────────────┬──────────────┬───────────┬─────────┐
│ Version  │ ChainType │ ChainRefLen  │ ChainRef     │ AddrLen   │ Address │
│ 2 bytes  │ 2 bytes   │ 1 byte       │ variable     │ 1 byte    │ variable│
│ 0x0001   │ 0x0000    │ N            │ BE(chainId)  │ 0x14      │ 20 bytes│
└──────────┴───────────┴──────────────┴──────────────┴───────────┴─────────┘
```

- **Version** `0x0001` — current ERC-7930 spec version.
- **ChainType** `0x0000` — the `eip155` namespace (all standard EVM chains).
- **ChainRefLen** — byte length of ChainRef.
- **ChainRef** — the chain ID encoded as a big-endian unsigned integer using the minimum number of bytes (no leading zeros).
- **AddrLen** `0x14` — 20 bytes for standard EVM addresses.
- **Address** — the raw address bytes.

For Alpen testnet (chain 8150) with address `0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045`:

```
0x 0001 0000 02 1fd6 14 d8da6bf26964af9d7eed9e03e53415d37aa96045
   ──── ──── ── ──── ── ────────────────────────────────────────────
   ver  type len ref  len address (20 bytes)
```

## Quick start

Python 3.7+, no dependencies.

```bash
# Encode an address on Alpen testnet (default chain-id = 8150)
python3 alpen_caip350.py --address 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

# Encode on Alpen mainnet
python3 alpen_caip350.py --address 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --chain-id 815

# Run built-in test vectors
python3 alpen_caip350.py --test
```

### Example output

```
CAIP-2  : eip155:8150
CAIP-10 : eip155:8150:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
Chain reference bytes : 0x1fd6
ERC-7930 (hex)        : 0x00010000021fd614d8da6bf26964af9d7eed9e03e53415d37aa96045

Field breakdown:
  Version          : 0x0001
  ChainType        : 0x0000  (eip155)
  ChainRefLength   : 0x02  (2 bytes)
  ChainReference   : 0x1fd6  (chain ID 8150)
  AddressLength    : 0x14  (20 bytes)
  Address          : 0xd8da6bf26964af9d7eed9e03e53415d37aa96045
```

## Golden test vectors

### Chain reference encoding

| Chain ID | Big-endian hex |
|----------|---------------|
| 1        | `0x01`        |
| 10       | `0x0a`        |
| 815      | `0x032f`      |
| 8150     | `0x1fd6`      |
| 11155111 | `0xaa36a7`    |

### Full ERC-7930 envelopes

Using address `0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045`:

| Chain              | ERC-7930 (hex)                                                  |
|--------------------|-----------------------------------------------------------------|
| Ethereum mainnet   | `0x00010000010114d8da6bf26964af9d7eed9e03e53415d37aa96045`      |
| Alpen testnet 8150 | `0x00010000021fd614d8da6bf26964af9d7eed9e03e53415d37aa96045`    |
| Alpen mainnet 815  | `0x0001000002032f14d8da6bf26964af9d7eed9e03e53415d37aa96045`    |

The Ethereum mainnet vector is taken directly from the ERC-7930 spec as a cross-check.

## Relevant specs

- [ERC-7930 — Interoperable Addresses](https://ercs.ethereum.org/ERCS/erc-7930)
- [CAIP-350 — Binary Serialization of Blockchain IDs and Addresses](https://chainagnostic.org/CAIPs/caip-350)
- [eip155 CAIP-350 Profile](https://namespaces.chainagnostic.org/eip155/caip350)
- [CAIP-2 — Blockchain ID Specification](https://chainagnostic.org/CAIPs/caip-2)
- [CAIP-10 — Account ID Specification](https://chainagnostic.org/CAIPs/caip-10)

## License

MIT
