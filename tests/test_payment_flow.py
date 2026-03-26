#!/usr/bin/env python3
"""
tests/test_payment_flow.py — Suite di test automatici per il sistema di pagamento offline

Esegui con:
    python -m pytest tests/test_payment_flow.py -v
    python -m pytest tests/test_payment_flow.py -v --tb=short
"""

from __future__ import annotations

import hashlib
import sys
import os
import time
import pytest

# Aggiungi i moduli al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host-app", "python"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bridge"))

from se_simulator import SecureElementSimulator, APDUException
from payment_flow import PaymentFlow, PaymentResult
from reconciliation_bridge import (
    ReconciliationBridge,
    OfflineTransaction,
    LocalValidator,
)


# ─── Fixture ──────────────────────────────────────────────────────────────────

@pytest.fixture
def alice() -> SecureElementSimulator:
    """Chip di Alice con 100.00€."""
    chip = SecureElementSimulator(balance_cents=10_000, name="Alice")
    chip.select()
    return chip


@pytest.fixture
def bob() -> SecureElementSimulator:
    """Chip di Bob con 50.00€."""
    chip = SecureElementSimulator(balance_cents=5_000, name="Bob")
    chip.select()
    return chip


@pytest.fixture
def empty_chip() -> SecureElementSimulator:
    """Chip vuoto con saldo zero."""
    chip = SecureElementSimulator(balance_cents=0, name="Empty")
    chip.select()
    return chip


@pytest.fixture
def flow(alice, bob) -> PaymentFlow:
    """Flusso di pagamento tra Alice e Bob."""
    return PaymentFlow(alice, bob, verbose=False)


# ─── TEST 1: Pagamento base ────────────────────────────────────────────────────

class TestBasicPayment:
    """Test del flusso di pagamento base."""

    def test_payment_success(self, alice, bob, flow):
        """Un pagamento valido deve completarsi con successo."""
        result = flow.execute(amount_cents=2500)  # 25.00€

        assert result.success is True
        assert result.amount_cents == 2500
        assert result.alice_new_balance == 7500   # 100€ - 25€ = 75€
        assert result.bob_new_balance   == 7500   # 50€ + 25€ = 75€
        assert result.error is None

    def test_payment_updates_balances(self, alice, bob, flow):
        """I saldi devono essere aggiornati correttamente dopo il pagamento."""
        flow.execute(amount_cents=1000)  # 10.00€

        assert alice.get_balance() == 9_000  # 100€ - 10€ = 90€
        assert bob.get_balance()   == 6_000  # 50€ + 10€ = 60€

    def test_payment_increments_counters(self, alice, bob, flow):
        """Ogni pagamento deve incrementare i contatori di entrambi i chip."""
        assert alice.get_counter() == 0
        assert bob.get_counter()   == 0

        flow.execute(amount_cents=500)

        assert alice.get_counter() == 1
        assert bob.get_counter()   == 1

    def test_multiple_payments(self, alice, bob, flow):
        """Più pagamenti consecutivi devono tutti riuscire."""
        flow.execute(amount_cents=1000)
        flow.execute(amount_cents=2000)
        flow.execute(amount_cents=500)

        # Alice: 100€ - 10€ - 20€ - 5€ = 65€
        # Bob:    50€ + 10€ + 20€ + 5€ = 85€
        assert alice.get_balance() == 6_500
        assert bob.get_balance()   == 8_500
        assert alice.get_counter() == 3
        assert bob.get_counter()   == 3

    def test_small_amount_payment(self, alice, bob, flow):
        """Deve funzionare anche per importi piccoli (1 centesimo)."""
        result = flow.execute(amount_cents=1)  # 0.01€

        assert result.success is True
        assert alice.get_balance() == 9_999
        assert bob.get_balance()   == 5_001


# ─── TEST 2: Validazione saldo ─────────────────────────────────────────────────

class TestBalanceValidation:
    """Test di validazione del saldo e dei limiti."""

    def test_insufficient_funds_rejected(self, alice, bob, flow):
        """Un pagamento superiore al saldo deve essere rifiutato."""
        result = flow.execute(amount_cents=20_000)  # 200€ > 100€

        assert result.success is False
        assert result.error is not None
        assert "insufficiente" in result.error.lower() or "insufficient" in result.error.lower()

    def test_insufficient_funds_no_balance_change(self, alice, bob, flow):
        """Un pagamento fallito non deve modificare i saldi."""
        old_alice = alice.get_balance()
        old_bob   = bob.get_balance()

        flow.execute(amount_cents=99_999)

        assert alice.get_balance() == old_alice
        assert bob.get_balance()   == old_bob

    def test_exact_balance_payment(self, alice, bob, flow):
        """Un pagamento esattamente uguale al saldo deve riuscire."""
        result = flow.execute(amount_cents=10_000)  # 100€ == saldo Alice

        assert result.success is True
        assert alice.get_balance() == 0

    def test_zero_amount_rejected(self, alice, bob):
        """Un pagamento di 0€ deve essere rifiutato."""
        with pytest.raises(APDUException) as exc_info:
            alice.initiate_payment(
                amount_cents      = 0,
                peer_pubkey_bytes = bob.get_public_key(),
                peer_counter      = bob.get_counter(),
            )
        assert exc_info.value.sw == 0x9140  # SW_INVALID_AMOUNT

    def test_empty_wallet_rejected(self, empty_chip, bob):
        """Un chip con saldo zero non può pagare."""
        with pytest.raises(APDUException) as exc_info:
            empty_chip.initiate_payment(
                amount_cents      = 100,
                peer_pubkey_bytes = bob.get_public_key(),
                peer_counter      = bob.get_counter(),
            )
        assert exc_info.value.sw == 0x9110  # SW_INSUFFICIENT_FUNDS


# ─── TEST 3: Sicurezza — Anti-replay ──────────────────────────────────────────

class TestAntiReplay:
    """Test di protezione contro attacchi replay."""

    def test_replay_attack_rejected(self, alice, bob, flow):
        """
        Un pacchetto di pagamento ripetuto deve essere rifiutato.
        Simula un attacco in cui Eve intercetta e reinvia una transazione.
        """
        # Esegui un pagamento normale
        bob_pubkey  = bob.get_public_key()
        bob_counter = bob.get_counter()

        tx_data = alice.initiate_payment(
            amount_cents      = 500,
            peer_pubkey_bytes = bob_pubkey,
            peer_counter      = bob_counter,
        )

        # Bob riceve e accredita
        bob.process_payment(
            amount_cents  = 500,
            pubkey_alice  = tx_data["pubkey_alice"],
            counter_alice = tx_data["counter_alice"],
            signature     = tx_data["signature"],
        )

        # Eve prova a reinviare lo stesso pacchetto
        with pytest.raises(APDUException) as exc_info:
            bob.process_payment(
                amount_cents  = 500,
                pubkey_alice  = tx_data["pubkey_alice"],
                counter_alice = tx_data["counter_alice"],  # stesso contatore!
                signature     = tx_data["signature"],
            )

        assert exc_info.value.sw == 0x9120  # SW_INVALID_COUNTER

    def test_counter_increases_monotonically(self, alice, bob, flow):
        """Il contatore deve solo aumentare, mai diminuire."""
        counters = []
        for _ in range(5):
            flow.execute(amount_cents=100)
            counters.append(alice.get_counter())

        # Verifica che i contatori siano strettamente crescenti
        for i in range(1, len(counters)):
            assert counters[i] > counters[i - 1], \
                f"Contatore non crescente: {counters[i]} <= {counters[i-1]}"


# ─── TEST 4: Sicurezza — Firma digitale ────────────────────────────────────────

class TestDigitalSignature:
    """Test dell'integrità crittografica delle transazioni."""

    def test_tampered_amount_rejected(self, alice, bob):
        """Una firma con importo modificato deve essere rifiutata."""
        bob_pubkey  = bob.get_public_key()
        bob_counter = bob.get_counter()

        # Alice firma per 100 centesimi
        tx_data = alice.initiate_payment(
            amount_cents      = 100,
            peer_pubkey_bytes = bob_pubkey,
            peer_counter      = bob_counter,
        )

        # Eve modifica l'importo (100 → 10000) ma usa la firma originale
        with pytest.raises(APDUException) as exc_info:
            bob.process_payment(
                amount_cents  = 10_000,  # importo falsificato!
                pubkey_alice  = tx_data["pubkey_alice"],
                counter_alice = tx_data["counter_alice"],
                signature     = tx_data["signature"],  # firma originale
            )

        assert exc_info.value.sw == 0x9130  # SW_INVALID_SIGNATURE

    def test_wrong_signature_rejected(self, alice, bob):
        """Una firma invalida deve essere rifiutata."""
        # Charlie è un terzo chip non coinvolto
        charlie = SecureElementSimulator(balance_cents=10_000, name="Charlie")
        charlie.select()

        bob_pubkey  = bob.get_public_key()
        bob_counter = bob.get_counter()

        # Alice firma la transazione
        tx_data = alice.initiate_payment(
            amount_cents      = 500,
            peer_pubkey_bytes = bob_pubkey,
            peer_counter      = bob_counter,
        )

        # Eve usa la firma di Charlie invece di quella di Alice
        charlie_tx = charlie.initiate_payment(
            amount_cents      = 500,
            peer_pubkey_bytes = bob_pubkey,
            peer_counter      = bob_counter,
        )

        with pytest.raises(APDUException) as exc_info:
            bob.process_payment(
                amount_cents  = 500,
                pubkey_alice  = tx_data["pubkey_alice"],
                counter_alice = tx_data["counter_alice"],
                signature     = charlie_tx["signature"],  # firma sbagliata!
            )

        assert exc_info.value.sw == 0x9130  # SW_INVALID_SIGNATURE

    def test_each_chip_has_unique_key(self):
        """Ogni chip deve avere una chiave pubblica unica."""
        chips = [SecureElementSimulator(balance_cents=1000) for _ in range(5)]
        for chip in chips:
            chip.select()

        pubkeys = [chip.get_public_key() for chip in chips]
        unique_pubkeys = set(pubkeys)

        assert len(unique_pubkeys) == len(chips), \
            "Due chip hanno la stessa chiave pubblica!"


# ─── TEST 5: Chip management ──────────────────────────────────────────────────

class TestChipManagement:
    """Test di gestione del chip (selezione, caricamento fondi, log)."""

    def test_chip_requires_select(self):
        """Il chip deve essere selezionato prima di usarlo."""
        chip = SecureElementSimulator(balance_cents=1000)
        # NON chiamo chip.select()

        with pytest.raises(APDUException):
            chip.get_balance()

    def test_load_funds(self, empty_chip):
        """Il caricamento di fondi deve aumentare il saldo."""
        empty_chip.load_funds(10_000)  # 100€

        assert empty_chip.get_balance() == 10_000

    def test_load_funds_resets_offline_spent(self, alice, bob, flow):
        """Il caricamento fondi deve resettare il contatore di spesa offline."""
        # Paga qualcosa offline
        flow.execute(amount_cents=1000)

        # Carica fondi (simula riconciliazione)
        alice.load_funds(5_000)

        # Ora dovrebbe poter spendere di nuovo fino al limite
        # (verifichiamo che non venga bloccato dal limite offline precedente)
        result = flow.execute(amount_cents=1000)
        assert result.success is True

    def test_transaction_log_recorded(self, alice, bob, flow):
        """Le transazioni devono essere registrate nel log."""
        flow.execute(amount_cents=1000)
        flow.execute(amount_cents=500)

        log_alice = alice.get_transaction_log()
        log_bob   = bob.get_transaction_log()

        assert len(log_alice) == 2
        assert len(log_bob)   == 2

    def test_transaction_log_amounts(self, alice, bob, flow):
        """Il log deve contenere gli importi corretti."""
        flow.execute(amount_cents=3500)  # 35.00€

        log_alice = alice.get_transaction_log()
        assert log_alice[0].amount_cents == 3500
        assert log_alice[0].direction    == "OUT"

        log_bob = bob.get_transaction_log()
        assert log_bob[0].amount_cents == 3500
        assert log_bob[0].direction    == "IN"


# ─── TEST 6: Bridge di riconciliazione ────────────────────────────────────────

class TestReconciliationBridge:
    """Test del bridge di riconciliazione."""

    def _make_tx(self, alice: SecureElementSimulator, bob: SecureElementSimulator,
                 amount_cents: int) -> OfflineTransaction:
        """Helper: crea una transazione valida."""
        bob_pubkey  = bob.get_public_key()
        bob_counter = bob.get_counter()

        tx_data = alice.initiate_payment(
            amount_cents      = amount_cents,
            peer_pubkey_bytes = bob_pubkey,
            peer_counter      = bob_counter,
        )
        alice.confirm_payment()

        payload = tx_data["payload"]
        return OfflineTransaction(
            tx_id           = hashlib.sha256(payload).hexdigest(),
            timestamp       = time.time(),
            amount_cents    = amount_cents,
            sender_pubkey   = tx_data["pubkey_alice"].hex(),
            receiver_pubkey = bob_pubkey.hex(),
            sender_counter  = tx_data["counter_alice"],
            signature       = tx_data["signature"].hex(),
            payload_hex     = payload.hex(),
        )

    def test_local_validator_accepts_valid_tx(self, alice, bob):
        """Il validatore locale deve accettare transazioni valide."""
        tx = self._make_tx(alice, bob, 500)

        validator = LocalValidator()
        is_valid, reason = validator.validate(tx)

        assert is_valid is True, f"Transazione valida rifiutata: {reason}"

    def test_local_validator_rejects_tampered_tx_id(self, alice, bob):
        """Il validatore deve rifiutare transazioni con tx_id manomesso."""
        tx = self._make_tx(alice, bob, 500)

        # Modifica il tx_id (manomissione)
        tx.tx_id = "00" * 32

        validator = LocalValidator()
        is_valid, reason = validator.validate(tx)

        assert is_valid is False
        assert "tx_id" in reason.lower() or "payload" in reason.lower()

    def test_bridge_dry_run(self, alice, bob, tmp_path):
        """In dry-run, il bridge deve validare senza inviare alla blockchain."""
        tx = self._make_tx(alice, bob, 1000)

        bridge = ReconciliationBridge(
            local_log_path = tmp_path / "test_log.json",
            dry_run        = True,
        )
        result = bridge.reconcile([tx])

        assert result.accepted == 1
        assert result.rejected == 0
        assert result.blockchain_batch_id is not None
        assert "DRY-RUN" in result.blockchain_batch_id

    def test_bridge_rejects_invalid_transactions(self, alice, bob, tmp_path):
        """Il bridge deve rifiutare transazioni con importo zero."""
        tx = self._make_tx(alice, bob, 500)
        tx.amount_cents = -100  # Importo non valido

        bridge = ReconciliationBridge(
            local_log_path = tmp_path / "test_log.json",
            dry_run        = True,
        )
        result = bridge.reconcile([tx])

        assert result.rejected == 1
        assert result.accepted == 0


# ─── TEST 7: Scenario end-to-end ──────────────────────────────────────────────

class TestEndToEnd:
    """Test di scenario completo: Alice paga più volte a Bob."""

    def test_coffee_shop_scenario(self):
        """
        Scenario: Alice entra in un bar e fa 3 acquisti.
        Verifica il comportamento corretto dell'intero sistema.
        """
        # Setup
        alice = SecureElementSimulator(balance_cents=5_000, name="Alice")  # 50€
        bob   = SecureElementSimulator(balance_cents=0, name="Bar-Bob")
        alice.select()
        bob.select()

        flow = PaymentFlow(alice, bob, verbose=False)

        # Acquisto 1: caffè 1.50€
        r1 = flow.execute(150)
        assert r1.success

        # Acquisto 2: cornetto 1.20€
        r2 = flow.execute(120)
        assert r2.success

        # Acquisto 3: succo 2.50€
        r3 = flow.execute(250)
        assert r3.success

        # Verifica saldi finali
        total_spent = 150 + 120 + 250  # 5.20€ = 520 centesimi
        assert alice.get_balance() == 5_000 - total_spent
        assert bob.get_balance()   == total_spent

        # Verifica contatori
        assert alice.get_counter() == 3
        assert bob.get_counter()   == 3

        # Verifica log
        alice_log = alice.get_transaction_log()
        assert len(alice_log) == 3
        assert all(tx.direction == "OUT" for tx in alice_log)

    def test_bidirectional_payments(self):
        """
        Test di pagamenti bidirezionali: Alice → Bob, poi Bob → Alice.
        """
        alice = SecureElementSimulator(balance_cents=10_000, name="Alice")
        bob   = SecureElementSimulator(balance_cents=10_000, name="Bob")
        alice.select()
        bob.select()

        # Alice paga Bob 30€
        flow_ab = PaymentFlow(alice, bob, verbose=False)
        r1 = flow_ab.execute(3_000)
        assert r1.success

        # Bob paga Alice 10€ (flusso inverso)
        flow_ba = PaymentFlow(bob, alice, verbose=False)
        r2 = flow_ba.execute(1_000)
        assert r2.success

        # Alice: 100€ - 30€ + 10€ = 80€
        # Bob:   100€ + 30€ - 10€ = 120€
        assert alice.get_balance() == 8_000
        assert bob.get_balance()   == 12_000
