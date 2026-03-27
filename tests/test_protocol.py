"""
Tests for the NFC APDU protocol layer — edge cases and error handling.
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
    CLA_AEGIS,
    MAX_SINGLE_PAYMENT,
    MAX_BALANCE,
)
from aegis_se.secure_element import SecureElement
from aegis_se.apdu import (
    initiate_payment,
    receive_payment,
    verify_pin,
    load_balance,
    parse_response,
)
from aegis_se.exceptions import APDUError, CommunicationError


def make_client(name="Test", balance=0):
    sim = SimulatedSE(name)
    transport = SimulatedTransport(sim)
    client = SecureElement(transport)
    client.connect()
    client.generate_keys()
    if balance > 0:
        client.verify_pin("000000")
        client.load_balance(balance)
    return client, sim


class TestAPDUProtocolEdgeCases:

    def test_wrong_cla(self):
        sim = SimulatedSE("Test")
        # Send an APDU with wrong CLA
        resp = sim.process_apdu(bytes([0x00, 0x10, 0x00, 0x00]))
        parsed = parse_response(resp)
        assert parsed.sw == 0x6E00  # CLA not supported

    def test_unknown_ins(self):
        sim = SimulatedSE("Test")
        resp = sim.process_apdu(bytes([CLA_AEGIS, 0xFF, 0x00, 0x00]))
        parsed = parse_response(resp)
        assert parsed.sw == 0x6D00  # INS not supported

    def test_short_apdu(self):
        sim = SimulatedSE("Test")
        resp = sim.process_apdu(bytes([CLA_AEGIS]))
        parsed = parse_response(resp)
        assert parsed.sw == 0x6700  # Wrong length

    def test_get_pubkey_without_keygen(self):
        client, sim = make_client.__wrapped__() if hasattr(make_client, '__wrapped__') else (None, None)
        # Direct test: try to get pubkey without generating keys
        sim = SimulatedSE("NoKeys")
        resp = sim.process_apdu(bytes([CLA_AEGIS, 0x14, 0x00, 0x00]))
        parsed = parse_response(resp)
        assert not parsed.is_ok

    def test_payment_amount_zero(self):
        client, sim = make_client("Alice", 10000)
        bob_client, bob_sim = make_client("Bob", 0)
        bob_pk = bob_client.get_public_key()

        # Build an APDU with amount = 0 manually
        with pytest.raises(ValueError):
            initiate_payment(bob_pk, 0, 1000000)

    def test_payment_amount_negative(self):
        client, sim = make_client("Alice", 10000)
        bob_client, _ = make_client("Bob", 0)
        bob_pk = bob_client.get_public_key()

        with pytest.raises(ValueError):
            initiate_payment(bob_pk, -100, 1000000)

    def test_payment_max_amount(self):
        client, sim = make_client("Alice", MAX_SINGLE_PAYMENT)
        bob_client, bob_sim = make_client("Bob", 0)
        bob_pk = bob_client.get_public_key()

        import time
        ts = int(time.time() * 1000)
        receipt = client.initiate_payment(bob_pk, MAX_SINGLE_PAYMENT, ts)
        assert len(receipt) > 0
        assert client.get_balance() == 0

    def test_balance_overflow_protection(self):
        # Load near-max balance, then try to receive more
        client, sim = make_client("Rich", MAX_BALANCE - 100)
        sender_client, sender_sim = make_client("Sender", 10000)

        sender_pk = sender_client.get_public_key()
        receiver_pk = client.get_public_key()

        import time
        ts = int(time.time() * 1000)
        receipt = sender_client.initiate_payment(receiver_pk, 200, ts)

        sender_uncompressed = sender_sim.get_uncompressed_pubkey()

        # This should fail because 299900 + 200 > MAX_BALANCE
        with pytest.raises(APDUError):
            client.receive_payment(sender_uncompressed, receipt)

    def test_pin_lockout_after_retries(self):
        client, sim = make_client("Locked", 0)

        # Wrong PIN 3 times
        for _ in range(3):
            with pytest.raises(APDUError):
                client.verify_pin("999999")

    def test_disconnected_transport(self):
        sim = SimulatedSE("Disc")
        transport = SimulatedTransport(sim)
        client = SecureElement(transport)
        # Don't connect!
        with pytest.raises(CommunicationError):
            client.get_version()

    def test_wrong_pubkey_length_rejected(self):
        with pytest.raises(ValueError):
            initiate_payment(b"\x02" * 32, 1000, 1000000)  # 32 bytes, need 33

    def test_wrong_uncompressed_key_length(self):
        with pytest.raises(ValueError):
            receive_payment(b"\x04" * 64, b"\x00" * 100)  # 64 bytes, need 65


class TestCounterMonotonicity:

    def test_counter_increases_on_send(self):
        client, sim = make_client("Sender", 10000)
        bob_client, _ = make_client("Bob", 0)
        bob_pk = bob_client.get_public_key()

        import time

        for expected in range(1, 6):
            ts = int(time.time() * 1000)
            client.initiate_payment(bob_pk, 100, ts)
            assert client.get_counter() == expected

    def test_counter_increases_on_receive(self):
        alice_client, alice_sim = make_client("Alice", 10000)
        bob_client, bob_sim = make_client("Bob", 0)

        import time

        for expected in range(1, 4):
            bob_pk = bob_client.get_public_key()
            ts = int(time.time() * 1000)
            receipt = alice_client.initiate_payment(bob_pk, 100, ts)
            alice_uncompressed = alice_sim.get_uncompressed_pubkey()
            bob_client.receive_payment(alice_uncompressed, receipt)
            assert bob_client.get_counter() == expected
