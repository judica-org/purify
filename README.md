# purify-cpp

> Warning: This project is a work in progress and is pending thorough review. Expect changes, incomplete areas, and rough edges.

This repository contains a C++ port of the `purify.py` reference implementation, plus native circuit construction and BPP-backed benchmarking on top of `secp256k1-zkp`.

Upstream reference material is available under [`reference/`](reference/) as optional git submodules.

## Repository layout

- `include/`: public library headers intended for downstream consumers
- `src/`: compiled support sources plus private headers
- `cli/`: CLI entrypoint plus private CLI-only runtime wiring for `purify_cpp`
- `bench/`: benchmark entrypoint for `bench_purify`
- `reference/`: local guide plus optional reference submodules for upstream `purify` and the benchmark fork of `secp256k1-zkp`
- `third_party/secp256k1-zkp`: cryptographic backend as a git submodule
- `third_party/nanobench`: benchmark harness as a git submodule

## Build

Initialize the library dependency submodule first:

```sh
git submodule update --init third_party/secp256k1-zkp
```

Configure and build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Top-level builds enable the CLI, benchmark, and docs targets by default. When this repository is added to another CMake project via `add_subdirectory(...)`, only the library target is enabled by default.
Top-level builds also enable the regression test target by default.

For multi-config generators such as Xcode, build benchmarks with `--config Release`.

### Using as a submodule

Add the repository as a git submodule, then wire it into the parent `CMakeLists.txt`:

```cmake
add_subdirectory(external/purifycpp)
target_link_libraries(your_target PRIVATE purify::purify)
```

Downstream code should include the library headers from the stable public include root:

```cpp
#include <purify.hpp>
#include <purify_bppp.hpp>
```

If you want the bundled CLI, benchmark, or docs targets while consuming the project as a subdirectory, enable them explicitly before `add_subdirectory(...)`:

```cmake
set(PURIFY_BUILD_CLI ON CACHE BOOL "" FORCE)
set(PURIFY_BUILD_BENCH ON CACHE BOOL "" FORCE)
set(PURIFY_BUILD_DOCS ON CACHE BOOL "" FORCE)
add_subdirectory(external/purifycpp)
```

### Benchmarks

Benchmarks require the additional `nanobench` submodule:

```sh
git submodule update --init third_party/nanobench
```

Then build `bench_purify` normally from the top-level project, or enable `PURIFY_BUILD_BENCH` before `add_subdirectory(...)` in a parent project.

### Tests

Build and run the regression suite with:

```sh
cmake -S . -B build -DPURIFY_BUILD_BENCH=OFF -DPURIFY_BUILD_DOCS=OFF -DPURIFY_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

To compare the generated verifier circuit against the checked-out Python reference implementation, initialize the
reference submodule and enable the extra regression:

```sh
git submodule update --init --depth 1 reference/purify
cmake -S . -B build -DPURIFY_BUILD_BENCH=OFF -DPURIFY_BUILD_DOCS=OFF -DPURIFY_BUILD_TESTS=ON -DPURIFY_BUILD_REFERENCE_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Generate API documentation with Doxygen:

```sh
cmake --build build --target docs
```

The generated HTML entrypoint is `build/docs/html/index.html`.

Optional reference material can be fetched separately:

```sh
git submodule update --init --depth 1 reference/purify reference/secp256k1-zkp
```

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
- BPP norm argument prove time
- BPP norm argument verify time

Run it with:

```sh
./build/bench_purify
```

If `bench_purify` is launched from a non-`Release` CMake configuration, it prints a warning before running. The benchmark target forces release optimization flags, but the intended path is still a full `Release` build.

Optional flags:

```text
--epochs N
--min-epoch-ms MS
```

Example output excerpt from the default benchmark configuration on a Macbook Air M4 16GB:

```text
purify benchmark setup
proof_system=legacy_bp_and_bppp_with_puresign_legacy_and_plusplus
message_bytes=4
gates=2048
constraints=4117
commitments=1
circuit_size_bytes=5878528
cache_eval_input_bytes=27
experimental_proof_size_bytes=1124
experimental_bppp_proof_size_bytes=909
norm_arg_n_vec_len=2048
norm_arg_l_vec_len=2048
norm_arg_c_vec_len=2048
norm_arg_proof_size_bytes=779
puresign_signature_size_bytes=64
puresign_legacy_proven_signature_size_bytes=1268
puresign_plusplus_proven_signature_size_bytes=1146
```

Nanobench now groups related rows by explicit unit, so the output is split into separate tables such as:


|          ns/circuit |           circuit/s |    err% |     total | purify
|--------------------:|--------------------:|--------:|----------:|:-------
|       28,132,875.00 |               35.55 |    1.7% |      0.14 | `verifier_circuit.native.build`
|          732,113.07 |            1,365.91 |   10.7% |      0.06 | :wavy_dash: `verifier_circuit.template.instantiate_native` (Unstable with ~14.6 iters. Increase `minEpochIterations` to e.g. 146)
|          367,025.65 |            2,724.61 |    5.4% |      0.06 | :wavy_dash: `verifier_circuit.template.instantiate_packed` (Unstable with ~29.0 iters. Increase `minEpochIterations` to e.g. 290)

|         ns/template |          template/s |    err% |     total | purify
|--------------------:|--------------------:|--------:|----------:|:-------
|       26,308,917.00 |               38.01 |    1.1% |      0.13 | `verifier_circuit.template.build`

|       ns/evaluation |        evaluation/s |    err% |     total | purify
|--------------------:|--------------------:|--------:|----------:|:-------
|        3,257,541.67 |              306.98 |    0.9% |      0.06 | `verifier_circuit.template.evaluate_partial`
|           20,213.51 |           49,471.85 |    0.6% |      0.05 | `verifier_circuit.template.evaluate_final`

|            ns/cache |             cache/s |    err% |     total | purify
|--------------------:|--------------------:|--------:|----------:|:-------
|       25,737,834.00 |               38.85 |    1.5% |      0.13 | `puresign_legacy.message_proof_cache.build`

|            ns/proof |             proof/s |    err% |     total | purify
|--------------------:|--------------------:|--------:|----------:|:-------
|      263,514,542.00 |                3.79 |    1.1% |      1.38 | `experimental_circuit.legacy_bp.prove`
|       40,884,667.00 |               24.46 |    1.8% |      0.21 | `experimental_circuit.legacy_bp.verify`
|      482,518,750.00 |                2.07 |    0.7% |      2.44 | `experimental_circuit.bppp_zk_norm_arg.prove`
|       53,572,666.00 |               18.67 |    0.4% |      0.27 | `experimental_circuit.bppp_zk_norm_arg.verify`
|       83,220,083.00 |               12.02 |    0.0% |      0.42 | `bppp.norm_arg.prove`
|       10,959,459.00 |               91.25 |    0.4% |      0.05 | `bppp.norm_arg.verify`

|     ns/resource_set |      resource_set/s |    err% |     total | purify
|--------------------:|--------------------:|--------:|----------:|:-------
|       82,586,208.00 |               12.11 |    0.3% |      0.41 | `experimental_circuit.legacy_bp_backend_resources.create`

|            ns/nonce |             nonce/s |    err% |     total | purify
|--------------------:|--------------------:|--------:|----------:|:-------
|          702,825.00 |            1,422.83 |    0.0% |      0.05 | `puresign_legacy.nonce.prepare`
|      317,086,083.00 |                3.15 |    3.0% |      1.68 | `puresign_legacy.nonce.prepare_with_proof`
|      303,744,208.00 |                3.29 |    3.4% |      1.66 | `puresign_legacy.nonce.prepare_with_proof_cached_template`
|      553,057,042.00 |                1.81 |    2.0% |      2.97 | `puresign_plusplus.nonce.prepare_with_proof`
|      523,149,250.00 |                1.91 |    0.5% |      2.66 | `puresign_plusplus.nonce.prepare_with_proof_cached_template`
|       66,666,083.00 |               15.00 |    1.7% |      0.34 | `puresign_legacy.nonce.verify_proof`
|       40,534,958.00 |               24.67 |    0.6% |      0.20 | `puresign_legacy.nonce.verify_proof_cached_template`
|       81,794,834.00 |               12.23 |    0.5% |      0.41 | `puresign_plusplus.nonce.verify_proof`
|       56,843,542.00 |               17.59 |    0.2% |      0.28 | `puresign_plusplus.nonce.verify_proof_cached_template`

|        ns/signature |         signature/s |    err% |     total | purify
|--------------------:|--------------------:|--------:|----------:|:-------
|          778,245.80 |            1,284.94 |    0.4% |      0.05 | `puresign_legacy.signature.sign`
|      316,064,416.00 |                3.16 |    0.1% |      1.58 | `puresign_legacy.signature.sign_with_proof`
|      284,111,375.00 |                3.52 |    0.4% |      1.53 | `puresign_legacy.signature.sign_with_proof_cached_template`
|      534,007,334.00 |                1.87 |    0.8% |      2.69 | `puresign_plusplus.signature.sign_with_proof`
|      506,387,791.00 |                1.97 |    0.7% |      2.74 | `puresign_plusplus.signature.sign_with_proof_cached_template`
|           29,724.02 |           33,642.83 |   25.3% |      0.06 | :wavy_dash: `puresign_legacy.signature.verify` (Unstable with ~352.8 iters. Increase `minEpochIterations` to e.g. 3528)
|       75,070,333.00 |               13.32 |    7.2% |      0.43 | :wavy_dash: `puresign_legacy.signature.verify_with_proof` (Unstable with ~1.0 iters. Increase `minEpochIterations` to e.g. 10)
|       38,522,875.00 |               25.96 |    1.2% |      0.19 | `puresign_legacy.signature.verify_with_proof_cached_template`
|       79,021,916.00 |               12.65 |    0.2% |      0.41 | `puresign_plusplus.signature.verify_with_proof`
|       54,723,916.00 |               18.27 |    0.7% |      0.28 | `puresign_plusplus.signature.verify_with_proof_cached_template`




The benchmark output still uses the `bppp` labels emitted by the `secp256k1-zkp` backend. In this repository's terminology, the implementation is against BPP.
