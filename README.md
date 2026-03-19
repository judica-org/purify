# purify-cpp

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

|          ns/circuit |           circuit/s |    err% |     total | purify |
|--------------------:|--------------------:|--------:|----------:|:-------|
|       52,372,000.00 |               19.09 |    0.0% |      0.05 | `verifier_circuit.native.build` |
|        3,898,250.00 |              256.53 |    0.0% |      0.00 | `verifier_circuit.template.instantiate_native` |
|          968,917.00 |            1,032.08 |    0.0% |      0.00 | `verifier_circuit.template.instantiate_packed` |

|            ns/proof |             proof/s |    err% |     total | purify |
|--------------------:|--------------------:|--------:|----------:|:-------|
|      829,548,458.00 |                1.21 |    0.0% |      0.83 | `experimental_circuit.legacy_bp.prove` |
|      119,583,291.00 |                8.36 |    0.0% |      0.12 | `experimental_circuit.legacy_bp.verify` |
|      107,984,375.00 |                9.26 |    0.0% |      0.11 | `bppp.norm_arg.prove` |
|       21,056,959.00 |               47.49 |    0.0% |      0.02 | `bppp.norm_arg.verify` |

The benchmark output still uses the `bppp` labels emitted by the `secp256k1-zkp` backend. In this repository's terminology, the implementation is against BPP.
