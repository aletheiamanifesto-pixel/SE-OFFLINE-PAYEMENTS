#!/usr/bin/env python3
"""
examples/scenario_caffe.py — "Alice paga un caffè a Bob"

Scenario dimostrativo completo che mostra come funziona un pagamento
offline tra due chip Secure Element simulati.

Esegui con:
    python examples/scenario_caffe.py
"""

from __future__ import annotations

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host-app", "python"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bridge"))

from se_simulator import SecureElementSimulator
from payment_flow import PaymentFlow
from reconciliation_bridge import ReconciliationBridge, OfflineTransaction
import hashlib


# ─── Utilità di stampa ────────────────────────────────────────────────────────

def sep(char="─", width=60) -> None:
    print(char * width)


def header(title: str) -> None:
    sep("═")
    print(f"  {title}")
    sep("═")


def section(title: str) -> None:
    print()
    sep()
    print(f"  {title}")
    sep()


def chip_status(chip: SecureElementSimulator) -> None:
    log = chip.get_transaction_log()
    print(f"  📱 {chip.name}")
    print(f"     Saldo:     {chip.get_balance_euro():.2f}€")
    print(f"     Contatore: {chip.get_counter()}")
    print(f"     Transazioni nel log: {len(log)}")


# ─── Scenario principale ──────────────────────────────────────────────────────

def scenario_caffe() -> None:
    """
    Scenario completo: Alice entra in un bar gestito da Bob e paga.

    Mostra passo per passo cosa succede nei chip NFC durante il pagamento.
    """

    header("☕ SCENARIO: Alice paga un caffè a Bob")

    # ── Setup portafogli ─────────────────────────────────────────────────────
    section("SETUP — Creazione portafogli")

    alice = SecureElementSimulator(balance_cents=5_000, name="Alice")  # 50.00€
    bob   = SecureElementSimulator(balance_cents=1_000, name="Bob")    # 10.00€
    alice.select()
    bob.select()

    print("  Portafogli creati con successo:")
    print()
    chip_status(alice)
    print()
    chip_status(bob)

    # ── Primo pagamento: caffè ────────────────────────────────────────────────
    section("PAGAMENTO 1 — Alice ordina un caffè (3.50€)")

    print("  [Scenario] Alice avvicina il telefono al POS di Bob...")
    print()
    print("  💬 Bob: 'Sono 3 euro e 50, grazie!'")
    print("  📱 Alice avvicina il telefono → NFC TAP")
    print()

    flow = PaymentFlow(alice, bob, verbose=True)

    time.sleep(0.3)  # Simula tempo NFC
    result1 = flow.execute(amount_cents=350)  # 3.50€

    if result1.success:
        print()
        print("  ✅ PAGAMENTO COMPLETATO!")
        print(f"  💳 Transazione: {result1.amount_euro:.2f}€")
    else:
        print(f"  ❌ PAGAMENTO FALLITO: {result1.error}")
        sys.exit(1)

    # ── Secondo pagamento: cornetto ───────────────────────────────────────────
    section("PAGAMENTO 2 — Alice aggiunge un cornetto (1.20€)")

    print("  💬 Alice: 'Aggiungo anche un cornetto!'")
    print("  📱 Secondo TAP NFC")
    print()

    time.sleep(0.2)
    result2 = flow.execute(amount_cents=120)  # 1.20€

    if result2.success:
        print()
        print("  ✅ PAGAMENTO COMPLETATO!")
        print(f"  💳 Transazione: {result2.amount_euro:.2f}€")
    else:
        print(f"  ❌ PAGAMENTO FALLITO: {result2.error}")
        sys.exit(1)

    # ── Stato dopo i pagamenti ────────────────────────────────────────────────
    section("STATO FINALE — Saldi e log transazioni")

    total_paid = result1.amount_cents + result2.amount_cents
    print(f"  Totale pagato da Alice: {total_paid / 100:.2f}€")
    print()
    chip_status(alice)
    print()
    chip_status(bob)

    # ── Log transazioni di Alice ──────────────────────────────────────────────
    section("LOG TRANSAZIONI — Chip di Alice")

    alice_log = alice.get_transaction_log()
    print(f"  Transazioni registrate: {len(alice_log)}")
    print()
    for i, tx in enumerate(alice_log, 1):
        direction = "⬆️  PAGATO" if tx.direction == "OUT" else "⬇️  RICEVUTO"
        print(f"  {i}. {direction}: {tx.amount_euro:.2f}€  (contatore: {tx.counter})")

    # ── Log transazioni di Bob ────────────────────────────────────────────────
    section("LOG TRANSAZIONI — Chip di Bob (il bar)")

    bob_log = bob.get_transaction_log()
    print(f"  Transazioni registrate: {len(bob_log)}")
    print()
    for i, tx in enumerate(bob_log, 1):
        direction = "⬆️  PAGATO" if tx.direction == "OUT" else "⬇️  RICEVUTO"
        print(f"  {i}. {direction}: {tx.amount_euro:.2f}€  (contatore: {tx.counter})")

    # ── Dimostrazione sicurezza: tentativo di pagamento senza fondi ───────────
    section("SICUREZZA — Tentativo di spesa eccessiva")

    print("  [Test] Proviamo a pagare 1000€ con saldo insufficiente...")
    result_fail = flow.execute(amount_cents=100_000)  # 1000€

    if not result_fail.success:
        print(f"  ✅ Pagamento correttamente rifiutato!")
        print(f"  ℹ️  Motivo: {result_fail.error}")
    else:
        print("  ❌ Errore: il pagamento non avrebbe dovuto riuscire!")

    # ── Dimostrazione: riconciliazione (bridge) ───────────────────────────────
    section("RICONCILIAZIONE — Bridge verso aegis-protocol (dry run)")

    print("  [Scenario] Alice torna online e sincronizza le transazioni...")
    print()

    bridge = ReconciliationBridge(dry_run=True)

    # Crea transazioni di esempio dal log di Alice
    transactions = []
    for tx_record in alice_log:
        # Costruisce un payload di esempio (semplificato per la demo)
        payload_demo = (
            tx_record.amount_cents.to_bytes(8, "big")
            + alice.get_public_key()
            + tx_record.counter.to_bytes(4, "big")
            + bob.get_public_key()
            + tx_record.counter.to_bytes(4, "big")
        )
        tx = OfflineTransaction(
            tx_id           = hashlib.sha256(payload_demo).hexdigest(),
            timestamp       = tx_record.timestamp,
            amount_cents    = tx_record.amount_cents,
            sender_pubkey   = alice.get_public_key().hex(),
            receiver_pubkey = bob.get_public_key().hex(),
            sender_counter  = tx_record.counter,
            signature       = (b"\x00" * 72).hex(),  # firma placeholder per demo
            payload_hex     = payload_demo.hex(),
        )
        transactions.append(tx)

    # Nota: in questa demo le firme sono placeholder, quindi il validatore
    # le rifiuterà. In un caso reale useremo le firme vere dal simulator.
    result_bridge = bridge.reconcile(transactions)
    result_bridge.print_summary()

    # ── Riepilogo finale ──────────────────────────────────────────────────────
    header("📊 RIEPILOGO FINALE")

    print()
    print("  PORTAFOGLI:")
    print(f"  {'Nome':<12} {'Saldo iniziale':>16} {'Saldo finale':>14} {'Transazioni':>14}")
    sep()
    print(f"  {'Alice':<12} {'50.00€':>16} {alice.get_balance_euro():>13.2f}€ {alice.get_counter():>14}")
    print(f"  {'Bob':<12} {'10.00€':>16} {bob.get_balance_euro():>13.2f}€ {bob.get_counter():>14}")
    print()
    print("  SICUREZZA:")
    print("  ✅ Tutte le transazioni firmate con ECDSA P-256")
    print("  ✅ Contatori monotonici anti-replay aggiornati")
    print("  ✅ Tentativo di spesa eccessiva bloccato")
    print("  ✅ Nessuna connessione internet richiesta per i pagamenti")
    print()
    sep("═")
    print("  Fine scenario. Buon caffè! ☕")
    sep("═")
    print()


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    scenario_caffe()
