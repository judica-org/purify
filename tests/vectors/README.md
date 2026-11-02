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

`construction_parent_v1_nondeciding.proof` is the adversarial acceptance
boundary vector for the same public two-anchor construction.

- Proof bytes: 12,466
- Proof SHA-256:
  `0dcdb66e11a0f9df2996ab0da2fa8fd79dcdc63877c5f20e9ef50949b17ae4f8`
- C++ prover-fixture SHA-256:
  `da7a9f02a401632725ca310688ae5d76ac4ac4ffbd2482601a3c8dd366ac4626`
- Purify fixture commit: `d6bcc0b`
- Purify qualifier commit: `36b9777`
- Nova revision: `ef88da858d1b7ade8fe4b36b585436adbde672ae`

The fixture changes only private recurrence witness data. Its public
construction statement and anchor descriptors are identical to the positive
vector. Both production recurrence steps, Nova folding, Spartan IPA
compression, and exact compressed verification succeed. The authenticated
pending root deliberately fails the native fixed-basis MSM.

The guarded qualification completed in 698.251 seconds: transparent setup
80.489 seconds, folding 4.508 seconds, compression 599.415 seconds, and final
verification 6.759 seconds. Public receipt acceptance must reject this vector
at `decide()` before issuing a `VerifiedConstructionReceipt`.
