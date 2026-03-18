# purify-cpp

This repository contains a C++ port of the `purify.py` reference implementation, plus native circuit construction and BPPP-backed benchmarking on top of `secp256k1-zkp`.

The original project README and other source reference material live under [`reference/`](reference/).

## Repository layout

- `src/`: C++ and C sources, including the core Purify implementation, runtime CLI, BPPP bridge, and benchmarks
- `reference/`: original Python reference code, verifier/proof artifacts, parameter generation scripts, and the original README
- `third_party/secp256k1-zkp`: cryptographic backend as a git submodule
- `third_party/nanobench`: benchmark harness as a git submodule

## Build

Initialize submodules first:

```sh
git submodule update --init --recursive
```

Configure and build:

```sh
cmake -S . -B build
cmake --build build --target purify_cpp bench_purify -j
```

The current CMake configuration builds with C++20, C11, warnings enabled, and `-O3` on non-MSVC toolchains.

## CLI

The `purify_cpp` binary provides:

```text
gen [<seckey>]
eval <seckey> <hexmsg>
verifier <hexmsg> <pubkey>
prove <hexmsg> <seckey>
run-circuit <hexmsg> <seckey>
commit-eval <seckey> <hexmsg> <blind32>
```

Example:

```sh
./build/purify_cpp eval \
  11427c7268288dddf0cd24af3d30524fd817a91e103e7e02eb28b78db81cb350b3d2562f45fa8ecd711d1becc02fa348cf2187429228e7aac6644a3da2824e93 \
  01234567
```

## Benchmarking

`bench_purify` measures:

- native circuit construction time
- estimated in-memory circuit size
- BPPP prove time
- BPPP verify time

Run it with:

```sh
./build/bench_purify
```

Optional flags:

```text
--epochs N
--min-epoch-ms MS
```
