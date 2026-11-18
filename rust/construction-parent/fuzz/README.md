# Construction-parent fuzz targets

Coverage-guided fuzzing of the two places the shipped verifier parses bytes
supplied by a peer before any proof is checked.

| Target | Entry point | Input |
| --- | --- | --- |
| `proof_codec` | `FixedSerdeShape::decode_canonical` under the qualified proof shape | proof bytes, laid over a real proof |
| `public_inputs` | `PublicInputs::parse` | statement digests, leaf counts and leaf descriptors |

The verifier artifact is not a target. It is authenticated against a
compiled-in length and digest before its header or payload is parsed, so its
parser is unreachable without that exact file.

```sh
cargo install cargo-fuzz
cd rust/construction-parent
cargo +nightly fuzz run proof_codec -- -max_len=15076
cargo +nightly fuzz run public_inputs -- -max_len=1024
```

CI only checks that the targets build. `verifier/tests/qualified_proofs.rs`
runs a fixed single-bit sweep over both checked-in proofs on every test run.
