# Decoder representations

The Decoder panel holds UTF-8 text, not arbitrary binary bytes.

## Octal and binary

These operations convert numeric runs, not character encodings. Octal encode
converts decimal ASCII digit runs to octal, and octal decode converts maximal
runs of 0 through 7 to decimal. Binary uses runs of 0 and 1 when decoding.
For example, decimal `72 105` becomes octal `110 151` or binary
`1001000 1101001`. Leading zeroes are not retained in converted runs.
Numbers exceeding u128 are left unchanged. Every other byte of the input,
including non-ASCII text and non-ASCII digit characters, is retained exactly.

## GZIP

- **GZIP -> Base64** takes UTF-8 text, compresses its bytes using GZIP, then
  displays standard padded base64 (RFC 4648 alphabet, no line breaks).
- **Base64 GZIP -> UTF-8** accepts that exact representation. It validates
  base64, checks the GZIP stream and checksum, and requires valid UTF-8 output.
  Malformed, truncated or corrupt data and non-UTF-8 output produce an error,
  not replacement characters or unchanged input. Decoded output is limited
  to 64 MiB.

This pair round-trips empty text, ASCII and non-ASCII text. The underlying
byte compressor/decompressor also round-trips arbitrary bytes, including all
256 byte values; the text UI intentionally rejects binary output it cannot
represent losslessly. Raw compressed text, including the lossy text that an
older experimental operation produced, is **not** silently reinterpreted.
Use a byte-capable client for compressed binary payloads.
