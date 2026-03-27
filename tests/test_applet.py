"""
Tests for the AEGIS Secure Element Simulator and APDU layer.
"""

import struct
import sys
import os
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "host-sdk"))

from simulator.se_simulator import (
    SimulatedSE,
    SimulatedTransport,
    SW_OK_BYTES,
    HEADER_LEN,
)
from aegis_se.secure_element import SecureElement
from aegis_se.apdu import (
    CLA_AEGIS,
    INS_GET_BALANCE,
    INS_GET_VERSION,
    get_version,
    get_balance,
    get_counter,
    get_public_key,
    parse_balance,
    parse_counter,
    parse_version,
    parse_response,
)
from aegis_se.exceptions import APDUError


# ── Fixtures ─────────────────────────────────────────────────────

@pytest.fixture
def se_sim():
    """Create a fresh SimulatedSE with keys generated."""
    se = SimulatedSE("TestSE")
    se.generate_keys()
    return se


@pytest.fixture
def se_client(se_sim):
    """Create a SecureElement client connected to a simulator."""
    transport = SimulatedTransport(se_sim)
    client = SecureElement(transport)
    client.connect()
    return client


@pytest.fixture
def funded_client(se_client):
    """A SecureElement client with 100€ balance loaded."""
    se_client.verify_pin("000000")
    se_client.load_balance(10000)  # 100.00 €
    return se_client


# ── Test SimulatedSE directly ────────────────────────────────────

class TestSimulatedSE:

    def test_generate_keys(self):
        se = SimulatedSE("Test")
        assert not se.has_keys
        pubkey = se.generate_keys()
        assert se.has_keys
        assert len(pubkey) == 33
        assert pubkey[0] in (0x02, 0x03)

    def test_initial_balance_is_zero(self):
        se = SimulatedSE("Test")
        assert se.balance == 0

    def test_initial_counter_is_zero(self):
        se = SimulatedSE("Test")
        assert se.counter == 0

    def test_compressed_pubkey_format(self, se_sim):
        pk = se_sim.get_compressed_pubkey()
        assert len(pk) == 33
        assert pk[0] in (0x02, 0x03)

    def test_uncompressed_pubkey_format(self, se_sim):
        pk = se_sim.get_uncompressed_pubkey()
        assert len(pk) == 65
        assert pk[0] == 0x04

    def test_sign_and_verify(self, se_sim):
        data = b"test message for signing"
        sig = se_sim.sign(data)
        assert len(sig) > 0
        pubkey = se_sim.get_uncompressed_pubkey()
        assert se_sim.verify(pubkey, data, sig)

    def test_verify_wrong_data_fails(self, se_sim):
        data = b"original data"
        sig = se_sim.sign(data)
        pubkey = se_sim.get_uncompressed_pubkey()
        assert not se_sim.verify(pubkey, b"tampered data", sig)


# ── Test APDU builders ──────────────────────────────────────────

class TestAPDUBuilders:

    def test_get_version_format(self):
        cmd = get_version()
        assert cmd[0] == CLA_AEGIS
        assert cmd[1] == INS_GET_VERSION

    def test_get_balance_format(self):
        cmd = get_balance()
        assert cmd[0] == CLA_AEGIS
        assert cmd[1] == INS_GET_BALANCE

    def test_parse_response_ok(self):
        raw = b"\x00\x01\x02\x90\x00"
        resp = parse_response(raw)
        assert resp.is_ok
        assert resp.data == b"\x00\x01\x02"

    def test_parse_response_error(self):
        raw = b"\x69\x85"
        resp = parse_response(raw)
        assert not resp.is_ok
        assert resp.sw == 0x6985

    def test_parse_balance(self):
        data = struct.pack(">I", 12345)
        assert parse_balance(data) == 12345

    def test_parse_counter(self):
        data = struct.pack(">I", 42)
        assert parse_counter(data) == 42

    def test_parse_version(self):
        data = bytes([1, 2, 3])
        assert parse_version(data) == (1, 2, 3)


# ── Test SecureElement client via simulator ──────────────────────

class TestSecureElementClient:

    def test_get_version(self, se_client):
        v = se_client.get_version()
        assert v == (1, 0, 0)

    def test_get_balance_initial(self, se_client):
        assert se_client.get_balance() == 0

    def test_get_counter_initial(self, se_client):
        assert se_client.get_counter() == 0

    def test_get_public_key(self, se_client):
        pk = se_client.get_public_key()
        assert len(pk) == 33

    def test_verify_pin_correct(self, se_client):
        se_client.verify_pin("000000")  # Should not raise

    def test_verify_pin_wrong(self, se_client):
        with pytest.raises(APDUError) as exc_info:
            se_client.verify_pin("999999")
        assert exc_info.value.sw & 0xFFF0 == 0x63C0

    def test_load_balance(self, se_client):
        se_client.verify_pin("000000")
        se_client.load_balance(5000)
        assert se_client.get_balance() == 5000
        assert se_client.get_balance_euro() == 50.0

    def test_load_balance_without_pin_fails(self, se_client):
        with pytest.raises(APDUError):
            se_client.load_balance(5000)

    def test_generate_keys(self):
        se = SimulatedSE("New")
        transport = SimulatedTransport(se)
        client = SecureElement(transport)
        client.connect()
        pk = client.generate_keys()
        assert len(pk) == 33


# ── Test Payment flow ────────────────────────────────────────────

class TestPaymentFlow:

    def _make_funded_se(self, name: str, balance: int):
        """Helper: create a funded SE client."""
        sim = SimulatedSE(name)
        transport = SimulatedTransport(sim)
        client = SecureElement(transport)
        client.connect()
        client.generate_keys()  # Generate keys first via client
        if balance > 0:
            client.verify_pin("000000")
            client.load_balance(balance)
        return client, sim

    def test_initiate_payment(self):
        alice_se, alice_sim = self._make_funded_se("Alice", 10000)
        bob_se, bob_sim = self._make_funded_se("Bob", 5000)

        receiver_pk = bob_se.get_public_key()
        import time
        ts = int(time.time() * 1000)

        receipt = alice_se.initiate_payment(receiver_pk, 2500, ts)
        assert len(receipt) >= HEADER_LEN
        assert alice_se.get_balance() == 7500
        assert alice_se.get_counter() == 1

    def test_full_p2p_payment(self):
        alice_se, alice_sim = self._make_funded_se("Alice", 10000)
        bob_se, bob_sim = self._make_funded_se("Bob", 5000)

        # Step 1: Get Bob's pubkey
        bob_pk = bob_se.get_public_key()

        # Step 2: Alice initiates
        import time
        ts = int(time.time() * 1000)
        receipt = alice_se.initiate_payment(bob_pk, 2500, ts)

        # Step 3: Get Alice's uncompressed pubkey for verification
        alice_uncompressed = alice_sim.get_uncompressed_pubkey()

        # Step 4: Bob receives
        bob_se.receive_payment(alice_uncompressed, receipt)

        # Verify final state
        assert alice_se.get_balance() == 7500   # 100 - 25 = 75
        assert bob_se.get_balance() == 7500     # 50 + 25 = 75
        assert alice_se.get_counter() == 1
        assert bob_se.get_counter() == 1

    def test_insufficient_funds(self):
        alice_se, _ = self._make_funded_se("Alice", 1000)  # only 10€
        bob_se, _ = self._make_funded_se("Bob", 0)
        bob_pk = bob_se.get_public_key()

        import time
        ts = int(time.time() * 1000)

        with pytest.raises(APDUError):
            alice_se.initiate_payment(bob_pk, 2000, ts)  # 20€ > 10€

    def test_multiple_payments(self):
        alice_se, alice_sim = self._make_funded_se("Alice", 10000)
        bob_se, bob_sim = self._make_funded_se("Bob", 5000)

        import time

        for i in range(3):
            bob_pk = bob_se.get_public_key()
            ts = int(time.time() * 1000)
            receipt = alice_se.initiate_payment(bob_pk, 1000, ts)
            alice_uncompressed = alice_sim.get_uncompressed_pubkey()
            bob_se.receive_payment(alice_uncompressed, receipt)

        assert alice_se.get_balance() == 7000  # 100 - 30 = 70
        assert bob_se.get_balance() == 8000    # 50 + 30 = 80
        assert alice_se.get_counter() == 3
        assert bob_se.get_counter() == 3

    def test_last_receipt(self):
        alice_se, alice_sim = self._make_funded_se("Alice", 10000)
        bob_se, _ = self._make_funded_se("Bob", 5000)

        bob_pk = bob_se.get_public_key()
        import time
        ts = int(time.time() * 1000)
        receipt = alice_se.initiate_payment(bob_pk, 2500, ts)

        stored = alice_se.get_last_receipt()
        assert stored == receipt


# ── Test Transaction Receipt parsing ─────────────────────────────

class TestTransactionReceipt:

    def test_parse_receipt(self):
        from aegis_se.transaction import TransactionReceipt

        alice_sim = SimulatedSE("Alice")
        alice_sim.generate_keys()
        bob_sim = SimulatedSE("Bob")
        bob_sim.generate_keys()

        # Create a simulated SE, fund it, and make a payment
        transport = SimulatedTransport(alice_sim)
        client = SecureElement(transport)
        client.connect()
        client.verify_pin("000000")
        client.load_balance(10000)

        bob_pk = bob_sim.get_compressed_pubkey()
        import time
        ts = int(time.time() * 1000)
        receipt_bytes = client.initiate_payment(bob_pk, 2500, ts)

        receipt = TransactionReceipt.from_bytes(receipt_bytes)
        assert receipt.version == 1
        assert receipt.amount_cents == 2500
        assert receipt.amount_euro == 25.0
        assert receipt.counter == 1
        assert len(receipt.sender_pubkey) == 33
        assert len(receipt.receiver_pubkey) == 33
        assert len(receipt.signature) > 0
        assert len(receipt.receipt_hash) == 64  # hex SHA-256

    def test_receipt_to_dict(self):
        from aegis_se.transaction import TransactionReceipt

        alice_sim = SimulatedSE("Alice")
        alice_sim.generate_keys()
        bob_sim = SimulatedSE("Bob")
        bob_sim.generate_keys()

        transport = SimulatedTransport(alice_sim)
        client = SecureElement(transport)
        client.connect()
        client.verify_pin("000000")
        client.load_balance(5000)

        bob_pk = bob_sim.get_compressed_pubkey()
        import time
        ts = int(time.time() * 1000)
        receipt_bytes = client.initiate_payment(bob_pk, 1000, ts)

        receipt = TransactionReceipt.from_bytes(receipt_bytes)
        d = receipt.to_dict()

        assert d["amount_cents"] == 1000
        assert d["amount_euro"] == 10.0
        assert "receipt_hash" in d
        assert "timestamp_iso" in d
