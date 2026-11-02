# Construction parent vectors

`construction_parent_v1_two_anchor.proof` is the canonical compressed Nova
proof used by the artifact-gated construction acceptance test.

- Proof bytes: 12,466
- Proof SHA-256:
  `c2a5fea4805eaa308a61f3374142bc95e6f7d983f5bf32e392983ab8c0a21b86`
- C++ prover-fixture SHA-256:
  `b32464f83d01e93777eb3fdfd5f00dfbca4ad4e537cf7c872285789ee2c4f41d`
- Purify generator commit: `ee191a2`
- Nova revision: `ef88da858d1b7ade8fe4b36b585436adbde672ae`

The proof was generated only after both exported anchor recurrences matched
the frozen relation, the final recursive root matched the independently
native-decided C++ root, and exact in-memory verification succeeded. The
guarded run completed with zero additional swapouts.

The proof hash identifies this test fixture. It is not a protocol constant;
compression may use fresh prover randomness. Production acceptance instead
binds the selected verifier suite, public construction inputs, external step
count, authenticated final state, and native final decision.
