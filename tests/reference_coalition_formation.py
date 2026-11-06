#!/usr/bin/env python3
# Copyright (c) 2026 Judica, Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Independent SHA-256 vectors for one-shot coalition formation."""

import hashlib


def tagged_hash(tag: bytes, message: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def main() -> None:
    genesis = bytes(range(0x00, 0x20))
    deployment = bytes(range(0x20, 0x40))
    transaction_id = bytes(range(0x40, 0x60))
    output_index = (0x78563412).to_bytes(4, "little")
    manifest = bytes(range(0x60, 0x80))

    permit_id = tagged_hash(
        b"Purify/Accountable/CoalitionPermit/v1",
        genesis + deployment + transaction_id + output_index,
    )
    core_digest = tagged_hash(
        b"Purify/Accountable/CoalitionFormation/v1",
        permit_id + manifest,
    )

    assert permit_id.hex() == (
        "823958198a32486bdb6778453458e73e"
        "f2e29f8b27723c0609976c3f9369d9b1"
    )
    assert core_digest.hex() == (
        "5cf18b61cb0320f98eb6f8189e5ad6e4"
        "bb1d17c619048ca40163c4e385245da5"
    )


if __name__ == "__main__":
    main()
