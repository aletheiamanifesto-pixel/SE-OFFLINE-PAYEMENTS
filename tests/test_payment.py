"""
Tests for the high-level PaymentProtocol and receipt handling.
"""

import sys
import os
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "host-sdk"))

from simulator.se_simulator import SimulatedSE, SimulatedTransport
from aegis_se.secure_element import SecureElement
from aegis_se.payment import PaymentProtocol, PaymentResult
from aegis_se.transaction import TransactionReceipt
from aegis_se.sync import ReceiptStore, SyncManager


def make_se(name: str, balance: int = 0) -> tuple[SecureElement, SimulatedSE]:
    """Create a funded SE client + underlying simulator."""
    sim = SimulatedSE(name)
    transport = SimulatedTransport(sim)
    client = SecureElement(transport)
    client.connect()
    client.generate_keys()
    if balance > 0:
        client.verify_pin("000000")
        client.load_balance(balance)
    return client, sim


class TestPaymentProtocol:

    def test_basic_payment(self):
        alice, alice_sim = make_se("Alice", 10000)
        bob, bob_sim = make_se("Bob", 5000)

        protocol = PaymentProtocol(alice, bob)
        result = protocol.pay(2500)

        assert result.success
        assert result.receipt is not None
        assert result.receipt.amount_cents == 2500
        assert result.sender_new_balance == 7500
        assert result.receiver_new_balance == 7500

    def test_payment_amount_euro(self):
        alice, _ = make_se("Alice", 10000)
        bob, _ = make_se("Bob", 0)

        protocol = PaymentProtocol(alice, bob)
        result = protocol.pay(1550)

        assert result.success
        assert result.amount_euro == 15.5

    def test_payment_insufficient_funds(self):
        alice, _ = make_se("Alice", 1000)  # only 10€
        bob, _ = make_se("Bob", 0)

        protocol = PaymentProtocol(alice, bob)
        result = protocol.pay(2000)  # 20€ > 10€

        assert not result.success
        assert result.error is not None

    def test_bidirectional_payments(self):
        alice, alice_sim = make_se("Alice", 10000)
        bob, bob_sim = make_se("Bob", 5000)

        # Alice → Bob  25€
        p1 = PaymentProtocol(alice, bob)
        r1 = p1.pay(2500)
        assert r1.success

        # Bob → Alice  10€
        p2 = PaymentProtocol(bob, alice)
        r2 = p2.pay(1000)
        assert r2.success

        # Alice: 100 - 25 + 10 = 85€
        assert alice.get_balance() == 8500
        # Bob: 50 + 25 - 10 = 65€
        assert bob.get_balance() == 6500

    def test_many_small_payments(self):
        alice, _ = make_se("Alice", 10000)
        bob, _ = make_se("Bob", 0)

        protocol = PaymentProtocol(alice, bob)
        for _ in range(10):
            result = protocol.pay(100)  # 1€ each
            assert result.success

        assert alice.get_balance() == 9000  # 100 - 10
        assert bob.get_balance() == 1000    # 0 + 10
        assert alice.get_counter() == 10
        assert bob.get_counter() == 10


class TestReceiptStore:

    def test_store_and_retrieve(self):
        alice, _ = make_se("Alice", 10000)
        bob, _ = make_se("Bob", 0)

        protocol = PaymentProtocol(alice, bob)
        result = protocol.pay(1000)

        store = ReceiptStore()
        store.store(result.receipt)

        assert store.count == 1
        assert store.unsynced_count == 1

    def test_mark_synced(self):
        alice, _ = make_se("Alice", 10000)
        bob, _ = make_se("Bob", 0)

        protocol = PaymentProtocol(alice, bob)
        result = protocol.pay(1000)

        store = ReceiptStore()
        store.store(result.receipt)
        store.mark_synced(result.receipt.receipt_hash)

        assert store.unsynced_count == 0

    def test_get_unsynced(self):
        alice, _ = make_se("Alice", 10000)
        bob, _ = make_se("Bob", 0)

        store = ReceiptStore()
        protocol = PaymentProtocol(alice, bob)

        for _ in range(3):
            result = protocol.pay(500)
            store.store(result.receipt)

        unsynced = store.get_unsynced()
        assert len(unsynced) == 3


class TestSyncManager:

    def test_sync_all(self):
        alice, _ = make_se("Alice", 10000)
        bob, _ = make_se("Bob", 0)

        store = ReceiptStore()
        protocol = PaymentProtocol(alice, bob)

        for _ in range(5):
            result = protocol.pay(200)
            store.store(result.receipt)

        sync = SyncManager("https://api.example.com", store)
        sync_result = sync.sync()

        assert sync_result.total == 5
        assert sync_result.settled == 5
        assert sync_result.success
        assert store.unsynced_count == 0
