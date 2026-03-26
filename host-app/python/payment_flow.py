#!/usr/bin/env python3
"""
payment_flow.py — Esegui un pagamento offline tra due chip simulati.

Uso:
    python payment_flow.py                        # usa valori di default
    python payment_flow.py --alice 100 --bob 50 --amount 25
    python payment_flow.py --interactive

Il modulo funziona sia come script autonomo (python payment_flow.py)
sia come libreria importabile (from payment_flow import PaymentFlow).
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Optional

# Importa il simulatore dalla stessa directory
import os
sys.path.insert(0, os.path.dirname(__file__))
from se_simulator import SecureElementSimulator, APDUException


# ─── Risultato pagamento ──────────────────────────────────────────────────────

@dataclass
class PaymentResult:
    """Risultato di un pagamento tra due chip."""

    success:            bool
    amount_cents:       int
    alice_old_balance:  int
    alice_new_balance:  int
    bob_old_balance:    int
    bob_new_balance:    int
    alice_counter:      int
    bob_counter:        int
    error:              Optional[str] = None

    @property
    def amount_euro(self) -> float:
        return self.amount_cents / 100

    def print_summary(self) -> None:
        """Stampa un riepilogo del pagamento."""
        print()
        if self.success:
            print("✅ Pagamento completato con successo!")
        else:
            print(f"❌ Pagamento fallito: {self.error}")

        print(f"   Importo: {self.amount_euro:.2f}€")
        print()
        print(f"   Alice: {self.alice_old_balance / 100:.2f}€ → {self.alice_new_balance / 100:.2f}€  "
              f"(contatore: {self.alice_counter})")
        print(f"   Bob:   {self.bob_old_balance / 100:.2f}€ → {self.bob_new_balance / 100:.2f}€  "
              f"(contatore: {self.bob_counter})")
        print()


# ─── Gestore del flusso di pagamento ─────────────────────────────────────────

class PaymentFlow:
    """
    Gestisce il flusso completo di un pagamento offline P2P.

    Il flusso segue esattamente il protocollo APDU:
      1. INITIATE_PAYMENT: Bob chiede ad Alice di pagare
      2. PROCESS_PAYMENT: Alice firma e Bob verifica/accredita
      3. CONFIRM_PAYMENT: Bob conferma, Alice deduce il saldo
    """

    def __init__(
        self,
        alice: SecureElementSimulator,
        bob:   SecureElementSimulator,
        verbose: bool = True,
    ) -> None:
        self.alice   = alice
        self.bob     = bob
        self.verbose = verbose

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def execute(self, amount_cents: int) -> PaymentResult:
        """
        Esegue un pagamento completo da Alice a Bob.

        Args:
            amount_cents: Importo in centesimi (es. 350 = 3.50€).

        Returns:
            PaymentResult con i dettagli del pagamento.
        """
        alice_old = self.alice.get_balance()
        bob_old   = self.bob.get_balance()

        self._log(f"\n{'─' * 50}")
        self._log(f"💳 Pagamento: {amount_cents / 100:.2f}€ (Alice → Bob)")
        self._log(f"{'─' * 50}")
        self._log(f"  Prima:  Alice={alice_old / 100:.2f}€, Bob={bob_old / 100:.2f}€")

        try:
            # ── Fase 1: Bob avvia la richiesta ────────────────────────────────
            self._log("\n[1/3] Bob richiede il pagamento (INITIATE_PAYMENT)...")

            bob_pubkey  = self.bob.get_public_key()
            bob_counter = self.bob.get_counter()

            # ── Fase 2: Alice firma ───────────────────────────────────────────
            self._log("[2/3] Alice verifica e firma la transazione...")

            tx_data = self.alice.initiate_payment(
                amount_cents      = amount_cents,
                peer_pubkey_bytes = bob_pubkey,
                peer_counter      = bob_counter,
            )

            self._log(f"      ✓ Firma ECDSA generata ({len(tx_data['signature'])} byte)")

            # ── Fase 3: Bob verifica e accredita ─────────────────────────────
            self._log("[3/3] Bob verifica la firma e accredita il saldo...")

            bob_new_balance = self.bob.process_payment(
                amount_cents   = amount_cents,
                pubkey_alice   = tx_data["pubkey_alice"],
                counter_alice  = tx_data["counter_alice"],
                signature      = tx_data["signature"],
            )

            self._log(f"      ✓ Firma verificata")
            self._log(f"      ✓ Saldo Bob aggiornato: {bob_new_balance / 100:.2f}€")

            # ── Fase 4: Alice confirma e deduce ───────────────────────────────
            alice_new_balance = self.alice.confirm_payment()

            self._log(f"      ✓ Saldo Alice aggiornato: {alice_new_balance / 100:.2f}€")

            result = PaymentResult(
                success            = True,
                amount_cents       = amount_cents,
                alice_old_balance  = alice_old,
                alice_new_balance  = alice_new_balance,
                bob_old_balance    = bob_old,
                bob_new_balance    = bob_new_balance,
                alice_counter      = self.alice.get_counter(),
                bob_counter        = self.bob.get_counter(),
            )

        except APDUException as e:
            result = PaymentResult(
                success            = False,
                amount_cents       = amount_cents,
                alice_old_balance  = alice_old,
                alice_new_balance  = alice_old,
                bob_old_balance    = bob_old,
                bob_new_balance    = bob_old,
                alice_counter      = self.alice.get_counter(),
                bob_counter        = self.bob.get_counter(),
                error              = str(e),
            )
            self._log(f"\n  ❌ Errore: {e}")

        return result


# ─── Modalità interattiva ─────────────────────────────────────────────────────

def run_interactive() -> None:
    """Avvia una sessione di pagamento interattiva."""
    print("\n🏦 === SISTEMA DI PAGAMENTO OFFLINE AEGIS EURO ===\n")

    try:
        alice_balance = float(input("Saldo iniziale Alice (€): "))
        bob_balance   = float(input("Saldo iniziale Bob   (€): "))
    except ValueError:
        print("Errore: inserisci valori numerici validi.")
        sys.exit(1)

    alice = SecureElementSimulator(int(alice_balance * 100), name="Alice")
    bob   = SecureElementSimulator(int(bob_balance * 100), name="Bob")
    alice.select()
    bob.select()

    flow = PaymentFlow(alice, bob, verbose=True)

    print(f"\nPortafogli creati:")
    print(f"  {alice.status()}")
    print(f"  {bob.status()}")

    while True:
        print("\n" + "─" * 40)
        try:
            cmd = input("Importo da pagare (€) oppure 'q' per uscire: ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if cmd.lower() in ("q", "quit", "exit", ""):
            break

        try:
            amount_euro = float(cmd)
            if amount_euro <= 0:
                print("Importo deve essere positivo.")
                continue
        except ValueError:
            print("Valore non valido. Inserisci un numero.")
            continue

        result = flow.execute(int(amount_euro * 100))
        result.print_summary()

        print(f"Stato attuale:")
        print(f"  {alice.status()}")
        print(f"  {bob.status()}")

    print("\n👋 Arrivederci!")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulatore pagamento offline AEGIS Euro",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  python payment_flow.py
  python payment_flow.py --alice 100 --bob 20 --amount 35.50
  python payment_flow.py --interactive
        """,
    )
    parser.add_argument("--alice",       type=float, default=100.0, help="Saldo iniziale Alice in euro (default: 100)")
    parser.add_argument("--bob",         type=float, default=50.0,  help="Saldo iniziale Bob in euro (default: 50)")
    parser.add_argument("--amount",      type=float, default=25.0,  help="Importo da pagare in euro (default: 25)")
    parser.add_argument("--interactive", action="store_true",       help="Modalità interattiva")
    parser.add_argument("--quiet",       action="store_true",       help="Nessun output verboso")

    args = parser.parse_args()

    if args.interactive:
        run_interactive()
        return

    # Modalità non interattiva: un singolo pagamento
    alice = SecureElementSimulator(int(args.alice * 100), name="Alice")
    bob   = SecureElementSimulator(int(args.bob   * 100), name="Bob")
    alice.select()
    bob.select()

    if not args.quiet:
        print("\n🏦 === PAGAMENTO OFFLINE AEGIS EURO ===")
        print(f"\nSetup:")
        print(f"  {alice.status()}")
        print(f"  {bob.status()}")

    flow   = PaymentFlow(alice, bob, verbose=not args.quiet)
    result = flow.execute(int(args.amount * 100))
    result.print_summary()

    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
