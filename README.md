# A Go library for the Snowblind blind signature scheme

[Snowblind](https://eprint.iacr.org/2023/1228.pdf) was introduced by Crites, Komlo, Maller, Tessaro, and Zhu in 2023. This Go library implements the plain blind signature scheme with $f(c,y) = c + y^5$, not the threshold version. Snowblind has many advantages compared to other existing blind signature schemes, including:

- concurrent security;
- small signatures;
- fast signing/verification;
- (relative) simplicity.

It's main ''flaw'' is that the security proof is in the Algebraic Group Model, but [the only blind signature scheme with concurrent security that avoids any "non-standard" assumptions entirely](https://eprint.iacr.org/2023/1780.pdf) requires an additional move, ~256x larger signatures, ~768x the communication cost, and is much slower.

This library instantiates Snowblind with [ristretto255 (Curve25519)](https://datatracker.ietf.org/doc/html/draft-hdevalence-cfrg-ristretto-01) and SHA512. It has not been security audited and is provided without warranty.

## Benchmark results

The following table compares this library to my [blindschnorr](https://github.com/fharding1/blindschnorr) library, which has the same API. Note that unlike blind Schnorr, Snowblind is concurrently secure.

| Operation     | Snowblind (ns) | Blind Schnorr (ns) |
| ------------- | -------------- | ------------------ |
| KeyGen        | 12769          | 12767              |
| NewCommitment | 78859          | 18113              |
| NewChallenge  | 169733         | 67051              |
| NewResponse   | 225.9          | 18.60              |
| NewSignature  | 235564         | 60490              |
| Verify        | 114144         | 66431              |


