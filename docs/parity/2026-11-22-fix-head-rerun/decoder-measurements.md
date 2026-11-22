# Real Burp Community 2026.11.2 Decoder measurements

Measured locally on November 22, 2026, through the desktop UI.

## Octal and Binary

These menus convert numeric tokens between decimal and the selected radix. They are not character-byte encoders.

| Operation | Exact input | Exact output |
|---|---|---|
| Encode as Octal | `Hi` | `Hi` |
| Encode as Binary | `Hi` | `Hi` |
| Encode as Octal | `72 105` | `110 151` |
| Encode as Binary | `72 105` | `1001000 1101001` |
| Decode as Octal | `\110\151` | `\72\105` |
| Decode as Octal | `110 151` | `72 105` |

## Gzip

Encode as Gzip on `hello` produces 25 bytes:

`1f8b08000000000000ffcb48cdc9c9070086a6103605000000`

The output switches to Hex view. Decode as Gzip on that output creates a third panel containing exactly `hello`.

## Smart decode

Input: `aHR0cHMlM0ElMkYlMkZleGFtcGxlLmNvbQ%3D%3D`

One Smart decode click creates panel 2 containing `aHR0cHMlM0ElMkYlMkZleGFtcGxlLmNvbQ==`. It only URL-decodes the padding. A Smart decode click in panel 2 does not advance this fixture. Manual Decode as Base64 creates panel 3 containing `https%3A%2F%2Fexample.com`. Smart decode there creates panel 4 containing `https://example.com`.

Thus the full desired decode is three transformations and four panels, but Smart decode alone stops after the first transformation on this input.

## Full Hash menu, in observed order

The dropdown is scrollable. This list is specific to the measured Community build and its Java providers.

```text
BLAKE2B-160
BLAKE2B-256
BLAKE2B-384
BLAKE2B-512
BLAKE2S-128
BLAKE2S-160
BLAKE2S-224
BLAKE2S-256
BLAKE3-256
DSTU7564-256
DSTU7564-384
DSTU7564-512
GOST3411
GOST3411-2012-256
GOST3411-2012-512
HARAKA-256
HARAKA-512
KECCAK-224
KECCAK-256
KECCAK-288
KECCAK-384
KECCAK-512
MD2
MD4
MD5
OID.1.0.10118.3.0.55
OID.1.2.804.2.1.1.1.1.2.2.1
OID.1.2.804.2.1.1.1.1.2.2.2
OID.1.2.804.2.1.1.1.1.2.2.3
OID.2.16.840.1.101.3.4.2.10
OID.2.16.840.1.101.3.4.2.11
OID.2.16.840.1.101.3.4.2.12
OID.2.16.840.1.101.3.4.2.7
OID.2.16.840.1.101.3.4.2.8
OID.2.16.840.1.101.3.4.2.9
PARALLELHASH128-256
PARALLELHASH256-512
RIPEMD128
RIPEMD160
RIPEMD256
RIPEMD320
SHA-1
SHA-224
SHA-256
SHA-384
SHA-512
SHA-512/224
SHA-512/256
SHA3-224
SHA3-256
SHA3-384
SHA3-512
SHAKE128-256
SHAKE256-512
SKEIN-1024-1024
SKEIN-1024-384
SKEIN-1024-512
SKEIN-256-128
SKEIN-256-160
SKEIN-256-224
SKEIN-256-256
SKEIN-512-128
SKEIN-512-160
SKEIN-512-224
SKEIN-512-256
SKEIN-512-384
SKEIN-512-512
SM3
TIGER
TUPLEHASH128-256
TUPLEHASH256-512
WHIRLPOOL
1.0.10118.3.0.55
1.2.804.2.1.1.1.1.2.2.1
1.2.804.2.1.1.1.1.2.2.2
1.2.804.2.1.1.1.1.2.2.3
2.16.840.1.101.3.4.2.10
2.16.840.1.101.3.4.2.11
2.16.840.1.101.3.4.2.12
2.16.840.1.101.3.4.2.7
2.16.840.1.101.3.4.2.8
2.16.840.1.101.3.4.2.9
```

Evidence: `hash-grid.png`, `hash-grid2.png`, individual scroll screenshots `hash-0.png` through `hash-13.png`; `octal-numeric.png`, `binary-numeric.png`, `octal-decode-slash.png`, `octal-decode-space.png`, `burp-gzip-roundtrip.png`, `burp-smart-nested.png`, `smart-after-base64.png`.
