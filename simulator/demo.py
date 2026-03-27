#!/usr/bin/env python3
"""
AEGIS Offline Payments — Interactive Demo
==========================================

Demonstrates a complete offline P2P payment between two simulated
Secure Elements (Alice → Bob), including:
    1. Key generation
    2. Balance loading
    3. P2P payment
    4. Receipt inspection
    5. Online synchronization

Run:
    python -m simulator.demo
    # or
    python simulator/demo.py
"""

from __future__ import annotations

import sys
import os
import time

# Ensure imports work regardless of working directory
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "host-sdk"))

from simulator.se_simulator import SimulatedSE, SimulatedTransport
from aegis_se.secure_element import SecureElement
from aegis_se.payment import PaymentProtocol
from aegis_se.transaction import TransactionReceipt
from aegis_se.sync import ReceiptStore, SyncManager


def separator(title: str = "") -> None:
    print(f"\n{'═' * 60}")
    if title:
        print(f"  {title}")
        print(f"{'═' * 60}")


def print_wallet(name: str, se: SecureElement) -> None:
    bal = se.get_balance()
    cnt = se.get_counter()
    print(f"  {name}: {bal / 100:.2f} €  (counter: {cnt})")


def main() -> None:
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║     🔐  AEGIS Offline Payments — Demo               ║
    ║     Secure Element P2P Payment Simulator             ║
    ╚══════════════════════════════════════════════════════╝
    """)

    # ── Step 1: Create two simulated Secure Elements ─────────────
    separator("STEP 1: Initialize Secure Elements")

    alice_sim = SimulatedSE("Alice")
    bob_sim = SimulatedSE("Bob")

    alice_transport = SimulatedTransport(alice_sim)
    bob_transport = SimulatedTransport(bob_sim)

    alice_se = SecureElement(alice_transport)
    bob_se = SecureElement(bob_transport)

    alice_se.connect()
    bob_se.connect()

    print("  ✅ Alice's SE initialized")
    print("  ✅ Bob's SE initialized")

    # Check version
    version = alice_se.get_version()
    print(f"  📱 Applet version: {version[0]}.{version[1]}.{version[2]}")

    # ── Step 2: Generate keys ────────────────────────────────────
    separator("STEP 2: Generate ECDSA Key Pairs")

    alice_pk = alice_se.generate_keys()
    bob_pk = bob_se.generate_keys()

    print(f"  🔑 Alice pubkey: {alice_pk.hex()[:24]}…")
    print(f"  🔑 Bob pubkey:   {bob_pk.hex()[:24]}…")

    # ── Step 3: Load balances (issuer operation) ─────────────────
    separator("STEP 3: Load Initial Balances (Issuer)")

    # Verify PIN first
    alice_se.verify_pin("000000")
    bob_se.verify_pin("000000")

    alice_se.load_balance(10000)  # 100.00 €
    bob_se.load_balance(5000)    #  50.00 €

    print("  💰 Loaded balances:")
    print_wallet("Alice", alice_se)
    print_wallet("Bob  ", bob_se)

    # ── Step 4: P2P Payment (Alice → Bob) ────────────────────────
    separator("STEP 4: Offline Payment — Alice pays Bob 25.00 €")

    print("  📱 Alice ──── NFC TAP ────► 📱 Bob")
    print()

    protocol = PaymentProtocol(alice_se, bob_se)
    result = protocol.pay(amount_cents=2500)  # 25.00 €

    if result.success:
        print("  ✅ Payment successful!")
        print(f"  📄 Receipt: {result.receipt}")
        print()
        print("  Updated balances:")
        print_wallet("Alice", alice_se)
        print_wallet("Bob  ", bob_se)
    else:
        print(f"  ❌ Payment failed: {result.error}")
        return

    # ── Step 5: Second payment (Bob → Alice) ─────────────────────
    separator("STEP 5: Offline Payment — Bob pays Alice 10.00 €")

    print("  📱 Bob ──── NFC TAP ────► 📱 Alice")
    print()

    protocol2 = PaymentProtocol(bob_se, alice_se)
    result2 = protocol2.pay(amount_cents=1000)  # 10.00 €

    if result2.success:
        print("  ✅ Payment successful!")
        print(f"  📄 Receipt: {result2.receipt}")
        print()
        print("  Updated balances:")
        print_wallet("Alice", alice_se)
        print_wallet("Bob  ", bob_se)
    else:
        print(f"  ❌ Payment failed: {result2.error}")

    # ── Step 6: Inspect receipts ─────────────────────────────────
    separator("STEP 6: Inspect Transaction Receipts")

    alice_receipt_data = alice_se.get_last_receipt()
    if alice_receipt_data:
        receipt = TransactionReceipt.from_bytes(alice_receipt_data)
        print(f"  Alice's last receipt:")
        d = receipt.to_dict()
        for key in ["amount_euro", "counter", "timestamp_iso", "receipt_hash"]:
            print(f"    {key}: {d[key]}")

    # ── Step 7: Online sync simulation ───────────────────────────
    separator("STEP 7: Online Synchronization")

    store = ReceiptStore()
    if result.receipt:
        store.store(result.receipt)
    if result2.receipt:
        store.store(result2.receipt)

    print(f"  📦 Receipts to sync: {store.unsynced_count}")

    sync_mgr = SyncManager("https://api.aegis-protocol.eu/v1", store)
    sync_result = sync_mgr.sync()

    print(f"  ✅ Settled: {sync_result.settled}/{sync_result.total}")
    print(f"  📦 Remaining unsynced: {store.unsynced_count}")

    # ── Summary ──────────────────────────────────────────────────
    separator("FINAL STATE")

    print_wallet("Alice", alice_se)
    print_wallet("Bob  ", bob_se)
    print()
    print("  Total transactions: Alice={}, Bob={}".format(
        alice_se.get_counter(), bob_se.get_counter()
    ))

    # Disconnect
    alice_se.disconnect()
    bob_se.disconnect()

    print()
    print("  🏁 Demo complete!")
    print()


if __name__ == "__main__":
    main()
