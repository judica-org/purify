# Aggregate Purify nonce: circuit and proof baseline

This series composes independently owned Purify hosts into circuits with one
summed output per coalition/topic group. It includes 100-member circuit
validation, multiple-topic proofs, and public-only verification of independently
completed coalition proofs. It does **not** implement private distributed
proving, succinct public proof compression, MuSig signing, key escrow, or a
production coalition protocol.

## Relation and API

For one exact evaluation input and an ordered roster of distinct hosts:

```text
for each member i:
    H_i binds that member's Purify secret
    r_i = Purify(secret_i, input)

R = (sum_i r_i) * G
```

`NativeBulletproofCircuitTemplate::instantiate_sum(hosts)` copies the local
circuits with disjoint indices, binds each host, and adds one output-sum
constraint. It retains explicit local bit equations and disables the legacy
global bit-prefix optimization. The combined gate count is padded once to a
power of two: the current 2,048-gate member relation requires 262,144 gates for
100 members. Empty/duplicate rosters, malformed dimensions, unsupported late
expressions, and size overflow are rejected.

`sum_assignments(hosts, assignments)` validates each local assignment, joins
the columns, pads with zero gates, and sums committed outputs. **Its caller
receives every private witness. This is not an MPC coordinator interface.**

The authenticated roster is an external verifier input. It is not repeated in
the proof bundle, but must be registered and available. Existing circuit
hashing binds host order and evaluation input; callers also supply versioned
protocol statement bindings. The coalition must define precise topic, roster,
signing-key, and activation bindings. A later signature protocol must specify
its aggregate-point parity rule; this baseline retains each member's raw
nonce output. An infinity aggregate must fail rather than select a
message-dependent replacement nonce.

## Proof backend and security boundary

The baseline uses `prove_experimental_circuit` and
`verify_experimental_circuit`, with `bppp::base_generator(context)` as the value
generator and no commitment blind. The honest fixture therefore yields
`R = sum(r_i) * G`. The generic arithmetic backend also permits nonzero output
blinds: these honest proofs do not establish a unique verifier-accepted nonce
point. The final nonce relation and its signature binding remain open.
For the single-group baseline, one compressed point and one arithmetic proof
are serialized; individual member nonce points are unnecessary in that bundle.

This is the imported **legacy Bulletproof arithmetic-circuit backend**, not the
current experimental BP++ circuit wrapper. The imported code is experimental
and has not received a new security audit here. Passing positive and negative
tests does not prove malicious-prover security.

Code review identified a prerequisite concern in the BP++ wrapper: its
constraint folding coefficients derive from public circuit/statement data
before a commitment to the original witness, and the reduced-witness commitment
requires a sound link back to the circuit. Local prover-side validation does
not establish that link for a verifier. This series neither repairs nor
establishes the security of that wrapper. No concrete forgery experiment was
completed. A reviewed implementation must establish the witness commitments,
challenge ordering, masked polynomial commitments, and verifier reconstruction
of the arithmetic-circuit protocol before adopting the BP++ aggregate path.
[BP++ sections 5.3–5.4](https://eprint.iacr.org/2022/510.pdf)

Independent local witnesses fit the paper's multiparty discussion, but that
discussion is informal. It is not a security proof or a 100-party implementation
for this code. Private computation of one shared host is a different workload.

## Scratch-space repair

The arithmetic backend previously allocated a fixed 16 MiB scratch region.
At 100 members, the compressed-circuit frame alone exceeds it. Scratch sizing
now accounts for actual gates, constraints, commitments, nested inner-product
frames, alignment, and the existing 16 MiB multiscalar workspace. Size arithmetic
and allocator-header addition are checked. Clones preserve grown capacity.

A one-gate regression with more than 524,288 constraints independently checks
constraint-count sizing, including cold and cloned-cache verification.

## Reproduction

The measurements below were recorded on 2026-10-27 from upstream `ebfeb03`.
The review branch carries the same baseline on upstream `373bb97` with the
scratch-sizing fix from PR #29. The local build uses AppleClang 16 on macOS
arm64, C++20, `-O2`, and enabled assertions:

```sh
git submodule update --init third_party/secp256k1-zkp third_party/nanobench
cmake -S . -B build/aggregate \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS_DEBUG=-O2 -DCMAKE_C_FLAGS_DEBUG=-O2 \
  -DPURIFY_CXX_STANDARD=20 \
  -DPURIFY_BUILD_BENCH=ON -DPURIFY_BUILD_TESTS=ON \
  -DPURIFY_BUILD_DOCS=OFF -DPURIFY_BUILD_CLI=OFF -DPURIFY_BUILD_FUZZ=OFF
cmake --build build/aggregate --target bench_aggregate_nonce purify_tests -j4
build/aggregate/purify_tests --suite aggregate_nonce --suite aggregate_nonce_100
build/aggregate/bench_aggregate_nonce --members 100
```

The benchmark accepts 1–100 members. It generates fresh keys and private prover
randomness, builds witnesses centrally, proves, serializes, parses, and verifies
with a cold verifier cache. JSON reports stages and proof sizes without printing
secrets. This target uses configured library flags rather than forcing release
optimization or `NDEBUG`.

Measurements are single local diagnostic runs, not percentiles or WAN results.
Proof bytes exclude the external roster, signature, application data, and
Bitcoin framing. Verification work and private communication do not become
logarithmic merely because the proof is short. Peak resident memory could not
be measured with the sandbox's restricted system diagnostics.

The initial 2026-10-27 size sweep used version 2 proof framing and completed with
exit status zero and successful serialized-proof verification in every case.
Current version 3 framing adds a four-byte output count; the raw proof and
single output-point sizes are unchanged:

| Members | Padded gates | Proof bundle bytes | Proving seconds | Cold verification seconds |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 2,048 | 1,162 | 0.365 | 0.117 |
| 10 | 32,768 | 1,419 | 6.882 | 1.924 |
| 25 | 65,536 | 1,483 | 12.001 | 3.924 |
| 50 | 131,072 | 1,547 | 24.207 | 7.836 |
| 100 | 262,144 | 1,612 | 49.391 | 15.875 |

That 100-member bundle contains a 1,574-byte arithmetic proof, one 33-byte nonce
point, and five framing bytes (nine in current version 3). Its circuit has
411,601 linear constraints.
These measurements establish compactness of this baseline, not acceptable
block-validation latency or distributed proving performance. Cold verification
is already a significant cost to address before deployment. The first separate
100-member run also verified, but the surrounding `/usr/bin/time -l` command
failed while querying a restricted system diagnostic; the table uses the later
direct benchmark runs with checked process exit statuses.

## Validation

The original single-topic series passed all 13 configured CTest suites. Its
aggregate proof, 100-member circuit, and large-constraint scratch suites also
passed with AddressSanitizer and UndefinedBehaviorSanitizer enabled. The local
sanitizer launcher initially inherited an invalid suppression-file path; the
successful run removed those inherited options:

```sh
env -u ASAN_OPTIONS -u UBSAN_OPTIONS -u LSAN_OPTIONS \
  ctest --test-dir build/sanitizers --output-on-failure \
  -R 'purify.tests.(aggregate_nonce|legacy_bulletproof)' -j2
```

Configure that build with `PURIFY_ENABLE_SANITIZERS=ON`, C++20, assertions
enabled, and benchmark/docs/CLI/fuzz targets disabled. The checked run used
`-O1` for the sanitizer build.

## Remaining implementation gates

1. Resolve the arithmetic-circuit protocol before adopting the BP++ path.
2. Specify permitted disclosures and an authenticated distributed transcript
   for local witness owners, including invalid inputs and aborts. Never send
   complete assignments or the aggregate nonce scalar to a coordinator.
3. Integrate partial signatures with the common challenge, final nonce parity,
   key-aggregation coefficients, and durable single-use authorization.
4. Test privacy/correctness with abort against 99 malicious participants and
   actual 100-party network conditions. Separate setup, consumable preprocessing,
   per-topic preparation, and final message-dependent signing.

The centralized benchmark is a baseline for this work, not evidence that these
gates have passed. No Char consensus or wallet code changes in this series.

## Multiple topics and coalitions

`purify/nonce_batch.hpp` defines an ordered `NonceBatchGroup` with the exact
evaluation input and ordered host roster. `nonce_batch_circuit(groups)` creates
one circuit with a separate committed scalar for each group.
`nonce_batch_assignments(groups, assignments)` validates and combines all local
witnesses. Its caller sees those witnesses; it is not a public aggregation API.

For group j, the relation is:

```text
v_j = sum over member i of Purify(secret_i, evaluation_input_j)
```

Every output is constrained separately. Equal and opposite changes to two
outputs cannot cancel. Hosts may recur across groups and topics, while each
individual roster rejects duplicate hosts. Repeated identical groups retain
separate outputs: coalition identity, coverage, activation, and stake counting
remain application rules. Callers must authenticate the supplied manifests.

The first implementation retains each group's power-of-two padding and pads
the combined circuit again. It does not yet share host-binding traces or secret
bit decompositions between topics. This is a correctness and measurement
baseline for those optimizations.

The generic arithmetic backend now carries an ordered vector of commitments.
The current wire encoding is version 3:

```text
version:u8 | proof_length:u32le | output_count:u32le
| compressed_points[output_count]:33 bytes each | proof_bytes
```

Counts and lengths must match the entire received frame before allocation.
Old frames are rejected. An empty prover blind span produces exact `v_j * G`
points; an explicit blind span must contain one scalar per output. PureSign's
single-nonce codec still requires exactly one output.

This last API is a generic Pedersen-output proof: its verifier also accepts
valid proofs with nonzero output blinding. The honest-path tests check exact
`v_j * G` points independently. They are not a security argument that the proof
alone forces zero blinding; deployment must establish the binding of the
combined nonce proof and Schnorr signature. No blinding masks were removed to
claim public aggregation.

## Public-only certificate preparation

After a coalition completes its proof, the certificate preparer must need only
public statements and serialized proofs. The integration test and
`bench_nonce_batch` enforce this API boundary. Each coalition prepares one proof
covering its topics and domains, and returns only its public groups and proof
bytes. The later stage reconstructs and verifies each statement without taking
keys, scalar nonces, assignments, or further signer messages.

That stage retains one proof per coalition. Its proof payload is linear in the
number of coalitions; it does not merge independent Fiat-Shamir transcripts.
Zero-knowledge is unnecessary for an outer proof whose witness consists only
of public child proofs, but that outer proof still needs a reviewed relation
verifying those proofs. Turning off blinding does not provide that relation.
[BP++ section 5.4](https://eprint.iacr.org/2022/510.pdf) concerns joint proving,
not public compression of already completed proofs.

The library defines no Char certificate wire format or quorum rules. The
benchmark reports the sum of serialized proof frames, excluding the public
manifest, signatures, and Bitcoin framing. The test also shows that reordering
completed coalition packets preserves their proofs, while changing topic order,
an evaluation input, or the coalition proof fails verification. Batch identifiers
never enter the deterministic nonce evaluation input.

Build and run with the same assertion-enabled configuration as above:

```sh
cmake --build build/aggregate --target bench_nonce_batch purify_tests -j4
build/aggregate/purify_tests --suite nonce_batch --suite nonce_certificate
build/aggregate/bench_nonce_batch --coalitions 2 --members 25 --topics 2 --domains 2
```

Each CLI dimension is 1 through 100, with at most 400 member evaluations in
one run. Topics denote distinct signing slots per domain. Coalition proving is
centralized and sequential in this benchmark; no MPC or network timing is
claimed. Proof generation and public verification each use cold backend
resources per coalition. Public statement reconstruction is timed separately.

The 2026-10-27 sweep completed with exit status zero and public verification
success in all three cases, using the same AppleClang 16, arm64, `-O2`, C++20,
assertion-enabled configuration. Times are single local runs, summed across
sequential coalitions, not MPC latency or throughput measurements:

| Coalitions N | Members M | Topics P | Domains K | Proof payload bytes | Proving seconds | Cold verification seconds |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 3 | 2 | 2 | 3,044 | 11.835 | 4.346 |
| 2 | 25 | 2 | 2 | 3,430 | 100.876 | 31.594 |
| 2 | 100 | 2 | 1 | 3,426 | 188.925 | 62.924 |

The 25-member case has eight nonce points and 262,144 padded gates per
coalition. Its payload is 3,148 raw proof bytes, 264 point bytes, and 18 framing
bytes. The 100-member case has four nonce points and 524,288 padded gates per
coalition; its payload is 3,276 raw proof bytes, 132 point bytes, and 18 framing
bytes. The latter frame is slightly smaller because it carries fewer outputs.

Coalition preparation took 1.700, 8.654, and 14.796 seconds respectively,
including key generation, witnesses, and circuit composition. Public statement
reconstruction and parsing added 0.262, 0.540, and 0.754 seconds to the listed
verification times. Compact proof payload does not remove this verification
cost or the requirement to make the public roster and topic manifest available.

The original multiple-topic series passed all 15 configured CTest suites. Five
focused suites also passed with AddressSanitizer and UndefinedBehaviorSanitizer:
legacy arithmetic proofs, summed nonce proofs, the 100-member circuit, multiple
topic composition, and public-only certificate preparation. The existing
`bench_purify`, `bench_aggregate_nonce`, and new `bench_nonce_batch` targets all
compile after the API migration. CLI help and six malformed configurations
return their expected statuses.
