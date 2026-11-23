"""Cryptographic, statistical, and adaptive firewall tests for Modules 1 & 2."""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from typer.testing import CliRunner

from qaegis.cli import app
from qaegis.core.bus import EventBus
from qaegis.core.config import QAegisConfig, RealityStampConfig
from qaegis.core.identity import DeviceIdentity, IdentityManager
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.chameleon_fw.crypto_agility import CryptoAgilityEngine
from qaegis.modules.chameleon_fw.detector import AdaptiveThreatDetector, ThreatTier
from qaegis.modules.chameleon_fw.features import TrafficObservation
from qaegis.modules.chameleon_fw.service import ChameleonFirewallService
from qaegis.modules.reality_stamp.merkle import MerkleTree, verify_merkle_proof
from qaegis.modules.reality_stamp.nist_tests import validate_entropy_batch
from qaegis.modules.reality_stamp.qrng import (
    EntropyHealthError,
    EntropySource,
    MultiSourceQrng,
    OsCsprngSource,
    QiskitHadamardQrngSource,
    xor_mix_streams,
)
from qaegis.modules.reality_stamp.service import RealityStampService
from qaegis.modules.reality_stamp.signer import verify_reality_stamp


class _BrokenZeroSource(EntropySource):
    @property
    def name(self) -> str:
        return "broken_zeros"

    async def fetch_bytes(self, num_bytes: int) -> bytes:
        return b"\x00" * num_bytes


@pytest.mark.crypto
def test_nist_sp_800_22_and_90b_validation() -> None:
    good = os.urandom(512)
    report_good = validate_entropy_batch(good, strict=False)
    assert report_good.passed is True
    assert all(t.passed for t in report_good.tests[:2])

    # All-zero stream must fail both 800-90B and 800-22
    zeros = b"\x00" * 512
    report_zeros = validate_entropy_batch(zeros, strict=True)
    assert report_zeros.passed is False
    assert report_zeros.tests[0].passed is False  # repetition count

    # Periodic stream (0xAA repeated) has 50% ones but fails Runs & 800-90B
    periodic = b"\xaa" * 512
    report_periodic = validate_entropy_batch(periodic, strict=True)
    assert report_periodic.passed is False


@pytest.mark.crypto
async def test_multi_source_qrng_and_rejection(metrics: QAegisMetrics) -> None:
    qrng = MultiSourceQrng(
        config=RealityStampConfig(qiskit_qrng_qubits=8, strict_nist_checks=False),
        sources=[QiskitHadamardQrngSource(num_qubits=8), OsCsprngSource()],
        metrics=metrics,
    )
    harvested = await qrng.harvest(num_bytes=64)
    assert len(harvested.raw_bytes) == 64
    assert "qiskit_hadamard_8q" in harvested.sources
    assert "linux_csprng" in harvested.sources
    assert harvested.health_report.passed is True

    # XOR mixing invariant check
    a = b"\x0f\xf0\xaa"
    b = b"\xf0\x0f\x55"
    assert xor_mix_streams([a, b]) == b"\xff\xff\xff"

    # Single broken source must raise EntropyHealthError
    broken_qrng = MultiSourceQrng(
        config=RealityStampConfig(strict_nist_checks=True),
        sources=[_BrokenZeroSource()],
        metrics=metrics,
    )
    with pytest.raises(EntropyHealthError):
        await broken_qrng.harvest(num_bytes=64, max_retries=1)


@pytest.mark.crypto
def test_merkle_tree_proofs_and_tamper_detection() -> None:
    tree = MerkleTree()
    for i in range(7):
        tree.append_raw(f"leaf-{i}".encode())

    for i in range(7):
        proof = tree.generate_proof(i)
        assert verify_merkle_proof(proof) is True

        # Tamper leaf hash
        bad_leaf = proof.model_copy(update={"leaf_hash": "00" * 32})
        assert verify_merkle_proof(bad_leaf) is False

        # Tamper root hash
        bad_root = proof.model_copy(update={"root_hash": "ff" * 32})
        assert verify_merkle_proof(bad_root) is False


@pytest.mark.crypto
async def test_reality_stamp_mldsa_slhdsa_and_persistence(
    event_bus: EventBus,
    device_identity: DeviceIdentity,
    storage: StorageEngine,
    metrics: QAegisMetrics,
) -> None:
    svc = RealityStampService(
        bus=event_bus,
        identity=device_identity,
        storage=storage,
        config=RealityStampConfig(strict_nist_checks=False),
        metrics=metrics,
    )
    await svc.start()

    # Primary ML-DSA-65 stamp
    stamp1 = await svc.stamp_perception(
        sensor_id="cam-front-01",
        perception_label="pedestrian_crossing",
        confidence=0.97,
        metadata={"bbox": [12, 34, 120, 240]},
        use_stateless_hash_sig=False,
    )
    assert "ML-DSA" in stamp1.algorithm
    assert stamp1.merkle_proof is not None
    ver1 = verify_reality_stamp(stamp1)
    assert ver1.valid is True
    assert ver1.merkle_proof_ok is True

    # Fallback SLH-DSA stateless hash-based stamp
    stamp2 = await svc.stamp_perception(
        sensor_id="lidar-top-01",
        perception_label="obstacle_static",
        confidence=0.99,
        use_stateless_hash_sig=True,
    )
    assert "SLH" in stamp2.algorithm
    ver2 = verify_reality_stamp(stamp2)
    assert ver2.valid is True
    assert ver2.merkle_proof_ok is True

    # Tamper payload confidence -> must fail verification
    tampered_payload = stamp1.payload.model_copy(update={"confidence": 0.10})
    tampered_stamp = stamp1.model_copy(update={"payload": tampered_payload})
    ver_bad = verify_reality_stamp(tampered_stamp)
    assert ver_bad.valid is False
    assert ver_bad.payload_hash_ok is False
    assert ver_bad.signature_ok is False

    # Restart service and verify Merkle tree hydrates identically from SQLite
    prev_root = svc.merkle_root
    await svc.stop()

    svc_reloaded = RealityStampService(
        bus=event_bus,
        identity=device_identity,
        storage=storage,
        metrics=metrics,
    )
    await svc_reloaded.start()
    assert svc_reloaded.tree_size == 2
    assert svc_reloaded.merkle_root == prev_root
    await svc_reloaded.stop()


@pytest.mark.crypto
def test_chameleon_onnx_detector_and_three_tier_crypto(
    qaegis_config: QAegisConfig,
    tmp_path: Path,
    metrics: QAegisMetrics,
) -> None:
    alice = IdentityManager(
        tmp_path / "alice_keys", "alice-node", qaegis_config.identity
    ).generate()
    bob = IdentityManager(tmp_path / "bob_keys", "bob-node", qaegis_config.identity).generate()

    onnx_path = tmp_path / "hndl_risk.onnx"
    detector = AdaptiveThreatDetector(
        config=qaegis_config.chameleon_fw,
        onnx_model_path=onnx_path,
    )
    assert onnx_path.is_file()

    low_obs = TrafficObservation(
        source="alice",
        destination="bob",
        protocol="lan",
        sensitivity="public",
        payload_bytes=b'{"temp_c": 21.5}',
        long_term_retention_years=0.1,
    )
    low_assess = detector.assess(low_obs)
    assert low_assess.tier == ThreatTier.STANDARD

    med_obs = TrafficObservation(
        source="alice",
        destination="bob",
        protocol="wan",
        sensitivity="confidential",
        payload_bytes=b"route_telemetry:" + os.urandom(128),
        long_term_retention_years=6.0,
    )
    med_assess = detector.assess(med_obs)
    assert med_assess.tier in (ThreatTier.ELEVATED, ThreatTier.QUANTUM_CRITICAL)

    crit_obs = TrafficObservation(
        source="alice",
        destination="bob",
        protocol="satellite",
        sensitivity="top_secret",
        payload_bytes=os.urandom(2048),
        long_term_retention_years=25.0,
    )
    crit_assess = detector.assess(crit_obs)
    assert crit_assess.tier == ThreatTier.QUANTUM_CRITICAL

    alice_crypto = CryptoAgilityEngine(alice, qaegis_config.chameleon_fw, metrics)
    bob_crypto = CryptoAgilityEngine(bob, qaegis_config.chameleon_fw, metrics)

    # Roundtrip across all three tiers
    for tier in (ThreatTier.STANDARD, ThreatTier.ELEVATED, ThreatTier.QUANTUM_CRITICAL):
        secret_msg = f"payload-for-{tier.value}".encode()
        env = alice_crypto.encrypt(
            plaintext=secret_msg,
            recipient=bob.public_bundle(),
            tier=tier,
            associated_data=b"hdr:v1",
        )
        recovered = bob_crypto.decrypt(env, expected_sender=alice.public_bundle())
        assert recovered == secret_msg

        if tier == ThreatTier.STANDARD:
            assert env.kem_ciphertext_b64 is None
            assert env.signature_b64 is None
        elif tier == ThreatTier.ELEVATED:
            assert env.kem_ciphertext_b64 is not None
            assert env.signature_b64 is None
        else:
            assert env.kem_ciphertext_b64 is not None
            assert env.signature_b64 is not None

            # Tampered ciphertext on QUANTUM_CRITICAL must fail PQC signature check
            ct_bytes = bytearray(base64.b64decode(env.ciphertext_b64))
            ct_bytes[0] ^= 0xFF
            tampered_env = env.model_copy(
                update={"ciphertext_b64": base64.b64encode(bytes(ct_bytes)).decode("ascii")}
            )
            with pytest.raises(ValueError, match="PQC signature verification failed"):
                bob_crypto.decrypt(tampered_env, expected_sender=alice.public_bundle())

    # Tampered ciphertext on ELEVATED must fail AES-GCM authentication
    elev_env = alice_crypto.encrypt(b"sensitive", bob.public_bundle(), ThreatTier.ELEVATED)
    ct_raw = bytearray(base64.b64decode(elev_env.ciphertext_b64))
    ct_raw[0] ^= 0x01
    bad_elev = elev_env.model_copy(
        update={"ciphertext_b64": base64.b64encode(bytes(ct_raw)).decode("ascii")}
    )
    with pytest.raises(InvalidTag):
        bob_crypto.decrypt(bad_elev)


@pytest.mark.crypto
async def test_chameleon_service_tier_events_and_cli_stamp_verify(
    event_bus: EventBus,
    qaegis_config: QAegisConfig,
    tmp_path: Path,
    metrics: QAegisMetrics,
) -> None:
    alice = IdentityManager(tmp_path / "svc_a", "svc-a", qaegis_config.identity).generate()
    bob = IdentityManager(tmp_path / "svc_b", "svc-b", qaegis_config.identity).generate()
    fw_a = ChameleonFirewallService(event_bus, alice, qaegis_config.chameleon_fw, metrics)
    fw_b = ChameleonFirewallService(event_bus, bob, qaegis_config.chameleon_fw, metrics)
    await fw_a.start()

    sub = event_bus.subscribe("chameleon.tier_changed")
    pkt = await fw_a.protect(
        TrafficObservation(
            source="svc-a",
            destination="svc-b",
            protocol="satellite",
            sensitivity="top_secret",
            payload_bytes=b"mission-orders",
            long_term_retention_years=20.0,
        ),
        recipient=bob.public_bundle(),
    )
    assert pkt.envelope.tier == ThreatTier.QUANTUM_CRITICAL
    assert fw_b.unprotect(pkt.envelope, expected_sender=alice.public_bundle()) == b"mission-orders"
    tier_event = sub.queue.get_nowait()
    assert tier_event.payload["new_tier"] == "QUANTUM_CRITICAL"
    await event_bus.unsubscribe(sub)


@pytest.mark.crypto
def test_cli_stamp_and_verify(tmp_path: Path) -> None:
    # CLI stamp + verify-stamp end-to-end
    cfg_file = tmp_path / "stamp_cli.yaml"
    cfg_file.write_text(
        (
            f"node_id: cli-stamp-node\n"
            f"data_dir: {tmp_path}/cli_data\n"
            f"keys_dir: {tmp_path}/cli_keys\n"
            f"db_path: {tmp_path}/cli_data/cli.db\n"
            f"reality_stamp:\n"
            f"  strict_nist_checks: false\n"
        ),
        encoding="utf-8",
    )
    stamp_out = tmp_path / "stamp.json"
    runner = CliRunner()
    res_create = runner.invoke(
        app,
        [
            "stamp",
            "--sensor",
            "cam0",
            "--label",
            "lane_clear",
            "--confidence",
            "0.95",
            "--output",
            str(stamp_out),
            "--config",
            str(cfg_file),
        ],
    )
    assert res_create.exit_code == 0, res_create.output
    res_verify = runner.invoke(app, ["verify-stamp", str(stamp_out)])
    assert res_verify.exit_code == 0, res_verify.output
    assert "Overall Valid" in res_verify.output
