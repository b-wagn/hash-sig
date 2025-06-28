# Hash-Based Signatures in Rust

This repository contains a *prototypical* Rust implementation of (synchronized) signatures based on tweakable hash functions and incomparable encodings.
The code has not been audited and is not meant to be used in production. It is a playground to explore and benchmark these signatures. Use it at your own risk.

## Schemes
The code implements a generic framework from [this paper](https://eprint.iacr.org/2025/055.pdf), which builds XMSS-like hash-based signatures from a primitive called incomparable encodings.
Hardcoded instantiations of this generic framework (using SHA3 or Poseidon2) are defined in `hashsig::signature::generalized_xmss`.
The parameters have been chosen based on the analysis in the paper using Python scripts. Details are as follows:

| Submodule        | Paper / Documentation                                     | Parameters Set With     |
|---------------|-----------------------------------------------------------|--------------------------|
| `instantiations_sha::*`        | [original paper](https://eprint.iacr.org/2025/055.pdf)    | [this repository](https://github.com/b-wagn/hashsig-parameters)   |
| `instantiations_poseidon::*`   | [original paper](https://eprint.iacr.org/2025/055.pdf)    | [this repository](https://github.com/b-wagn/hashsig-parameters)   |
| `instantiations_poseidon_top_level::*`   | new document (soon released), inspired by [this](https://eprint.iacr.org/2025/889.pdf)  | [this repository](https://github.com/b-wagn/hypercube-hashsig-parameters)   |

Instantiations for different key lifetimes and different encodings are given in these modules.

## Tests

Run the tests with

```
cargo test
```

By default, this will exclude some of the tests. In particular, correctness tests for real instantiations take quite long and are excluded.
If you want to run *all* tests, you can use

```
cargo test --release --features slow-tests
```

Removing the `--release` is also an option but tests will take even longer.

## Benchmarks

Benchmarks are provided using criterion.
They take a while, as key generation is expensive, and as a large number of schemes are benchmarked.
Run them with

```
cargo bench
```

The schemes that are benchmarked are hardcoded instantiations of the generic framework, which are defined in `hashsig::signature::generalized_xmss`.
The parameters of these instantiations have been chosen carefully with the aim to achieve a desired security level.
By default, key generation is not benchmarked. There are two options to benchmark it:
1. add the option `--features with-gen-benches-sha` or `--features with-gen-benches-poseidon` or `--features with-gen-benches-poseidon-top-level` to `cargo bench`. Note that this will make benchmarks very slow, as key generation will be repeated within the benchmarks. Especially for Poseidon, this is not recommended.
2. use code similar to the one provided in `src/bin/main.rs` and run it with `cargo run --release`.

If criterion only generates json files, one way to extract all means for all benchmarks easily (without re-running criterion) is to run

```
python3 benchmark-mean.py target
```

Confidence intervals can also be shown via

```
python3 benchmark-mean.py target --intervals
```

## License

Apache Version 2.0.