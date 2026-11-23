"""Cryptographic SHA-256 Merkle Tree audit log with RFC 6962 domain separation."""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel

from qaegis.core.identity import constant_time_equal

LEAF_DOMAIN_PREFIX = b"\x00"
NODE_DOMAIN_PREFIX = b"\x01"


def hash_leaf(data: bytes) -> bytes:
    """Compute domain-separated leaf hash SHA-256(0x00 || data)."""
    return hashlib.sha256(LEAF_DOMAIN_PREFIX + data).digest()


def hash_internal(left: bytes, right: bytes) -> bytes:
    """Compute domain-separated internal node hash SHA-256(0x01 || left || right)."""
    return hashlib.sha256(NODE_DOMAIN_PREFIX + left + right).digest()


class MerkleProofStep(BaseModel):
    """Single sibling step along a Merkle inclusion path."""

    position: Literal["left", "right"]
    sibling_hash: str


class MerkleProof(BaseModel):
    """Self-contained cryptographic proof that a leaf belongs to a Merkle root."""

    leaf_index: int
    tree_size: int
    leaf_hash: str
    root_hash: str
    steps: list[MerkleProofStep]


def verify_merkle_proof(proof: MerkleProof) -> bool:
    """Verify a Merkle inclusion proof purely from leaf hash, steps, and root hash."""
    if proof.leaf_index < 0 or proof.leaf_index >= proof.tree_size:
        return False
    try:
        current = bytes.fromhex(proof.leaf_hash)
        expected_root = bytes.fromhex(proof.root_hash)
    except ValueError:
        return False

    for step in proof.steps:
        try:
            sibling = bytes.fromhex(step.sibling_hash)
        except ValueError:
            return False
        if step.position == "left":
            current = hash_internal(sibling, current)
        else:
            current = hash_internal(current, sibling)
    return constant_time_equal(current, expected_root)


class MerkleTree:
    """Append-only binary SHA-256 Merkle Tree with inclusion proof generation."""

    def __init__(self, leaf_hashes: list[bytes] | None = None) -> None:
        self._leaves: list[bytes] = list(leaf_hashes) if leaf_hashes else []

    @classmethod
    def from_hex_leaves(cls, hex_leaves: list[str]) -> MerkleTree:
        """Reconstruct a MerkleTree from persisted hex-encoded leaf hashes."""
        return cls([bytes.fromhex(h) for h in hex_leaves])

    @property
    def size(self) -> int:
        return len(self._leaves)

    @property
    def root_hex(self) -> str:
        """Compute the current Merkle root as a 64-char hex string."""
        if not self._leaves:
            return hashlib.sha256(b"").hexdigest()
        return self._build_levels()[-1][0].hex()

    def append_raw(self, raw_payload: bytes) -> tuple[int, str, str]:
        """Hash `raw_payload` as a domain-separated leaf and return (index, leaf_hex, root_hex)."""
        leaf = hash_leaf(raw_payload)
        self._leaves.append(leaf)
        idx = len(self._leaves) - 1
        return idx, leaf.hex(), self.root_hex

    def append_leaf_hash(self, leaf_hex: str) -> tuple[int, str]:
        """Append an already-hashed leaf hex digest and return (index, root_hex)."""
        self._leaves.append(bytes.fromhex(leaf_hex))
        return len(self._leaves) - 1, self.root_hex

    def generate_proof(self, leaf_index: int) -> MerkleProof:
        """Generate a verifiable inclusion proof for `leaf_index`."""
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            raise IndexError(f"Leaf index {leaf_index} out of bounds for tree size {self.size}")

        levels = self._build_levels()
        steps: list[MerkleProofStep] = []
        idx = leaf_index

        for level in levels[:-1]:
            if idx % 2 == 0:
                sibling_idx = idx + 1 if idx + 1 < len(level) else idx
                steps.append(
                    MerkleProofStep(
                        position="right",
                        sibling_hash=level[sibling_idx].hex(),
                    )
                )
            else:
                sibling_idx = idx - 1
                steps.append(
                    MerkleProofStep(
                        position="left",
                        sibling_hash=level[sibling_idx].hex(),
                    )
                )
            idx //= 2

        return MerkleProof(
            leaf_index=leaf_index,
            tree_size=len(self._leaves),
            leaf_hash=self._leaves[leaf_index].hex(),
            root_hash=levels[-1][0].hex(),
            steps=steps,
        )

    def _build_levels(self) -> list[list[bytes]]:
        levels: list[list[bytes]] = [list(self._leaves)]
        while len(levels[-1]) > 1:
            current = levels[-1]
            next_level: list[bytes] = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                next_level.append(hash_internal(left, right))
            levels.append(next_level)
        return levels
