# Reference Material

This directory contains optional upstream reference repositories as git submodules.
They are not required for building `purify-cpp`.

Initialize both reference submodules:

```sh
git submodule update --init --depth 1 reference/purify reference/secp256k1-zkp
```

Initialize one reference only:

```sh
git submodule update --init --depth 1 reference/purify
git submodule update --init --depth 1 reference/secp256k1-zkp
```

Tracked upstreams:

- `reference/purify`: `https://github.com/jonasnick/purify.git` on `master`
- `reference/secp256k1-zkp`: `https://github.com/jonasnick/secp256k1-zkp.git` on `bulletproof-musig-dn-benches`

Required build dependencies remain under `third_party/`:

```sh
git submodule update --init third_party/secp256k1-zkp third_party/nanobench
```
