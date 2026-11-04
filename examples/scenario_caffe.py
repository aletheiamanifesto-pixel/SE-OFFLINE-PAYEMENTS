"""
scenario_caffe.py — Scenario: Alice compra un caffè al bar di Bob ☕

Immagina una bella mattina a Roma. Alice entra nel bar di Bob,
ordina un espresso e un cornetto. Nessuno dei due ha internet
(il Wi-Fi del bar è giù come al solito), ma non importa:
con AEGIS e il Secure Element, il pagamento avviene offline,
sicuro come pagare in contanti, ma tracciabile come un bonifico.

Questo esempio mostra come il sistema funziona nella vita reale,
dal primo contatto NFC fino alla ricevuta firmata digitalmente.

Esecuzione: python examples/scenario_caffe.py
"""

import struct
import sys
import time
from pathlib import Path

# Permette di lanciare lo script direttamente (python examples/...) senza pip install
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from host_app.python.se_simulator import SecureElementSimulator
from bridge.reconciliation_bridge import ReconciliationBridge


def scenario_caffe():
    """
    Scenario completo: Alice compra un caffè al bar di Bob.

    Prezzi del bar di Bob (come in un vero bar romano):
        ☕ Espresso:    1.20€
        🥐 Cornetto:    1.50€
        🧾 Totale:      2.70€
        (arrotondato: 3.50€ con mancia... Alice è generosa!)
    """

    print("\n" + "☕" * 30)
    print("  ☀️  BUONGIORNO! Scenario: Il Bar di Bob")
    print("☕" * 30)

    print("""
    📍 Luogo: Bar "Da Bob", Via del Corso, Roma
    🕘 Ora: 8:30 del mattino
    🌤️  Il Wi-Fi del bar è fuori servizio (come sempre!)
    
    👩 Alice: impiegata, ha il telefono con AEGIS wallet
    👨 Bob: barista, ha il POS offline con AEGIS
    """)

    # --- Preparazione dei Secure Element ---
    # Alice ha caricato il wallet ieri sera (100.00€)
    # Bob ha il fondo cassa della mattina (200.00€)
    print("📱 Inizializzazione dei dispositivi...\n")

    alice_wallet = SecureElementSimulator(initial_balance=10000)  # 100.00€
    bob_pos = SecureElementSimulator(initial_balance=20000)       # 200.00€

    print(f"  👩 Alice: portafoglio AEGIS con {alice_wallet.get_balance() / 100:.2f}€")
    print(f"  👨 Bob: cassa AEGIS con {bob_pos.get_balance() / 100:.2f}€")

    # --- Il conto ---
    prezzo_caffe = 350  # 3.50€ (espresso + cornetto, arrotondato con mancia)
    prezzo_euro = prezzo_caffe / 100.0

    print(f"\n🧾 ═══════════════════════════════")
    print(f"   SCONTRINO — Bar 'Da Bob'")
    print(f"   ─────────────────────────────")
    print(f"   ☕ Espresso         1.20€")
    print(f"   🥐 Cornetto         1.50€")
    print(f"   💝 Mancia           0.80€")
    print(f"   ─────────────────────────────")
    print(f"   🧮 TOTALE:          {prezzo_euro:.2f}€")
    print(f"═══════════════════════════════════\n")

    # --- FASE 1: Connessione NFC (SELECT) ---
    print("📶 Alice avvicina il telefono al POS di Bob...")
    print("   *bip* Connessione NFC stabilita!\n")

    apdu_select = SecureElementSimulator.build_apdu(0x00, 0xA4)
    alice_wallet.process_apdu(apdu_select)
    bob_pos.process_apdu(apdu_select)

    # --- FASE 2: Il POS chiede il pagamento ---
    print(f"💳 Bob: 'Sono {prezzo_euro:.2f}€, grazie!'")
    print(f"📱 Alice: 'Pago con AEGIS!' *appoggia il telefono*\n")

    # --- FASE 3: Addebito da Alice ---
    print("💸 Addebito in corso dal wallet di Alice...")
    successo_debit = alice_wallet.debit(prezzo_caffe)

    if not successo_debit:
        print("  ❌ Ops! Saldo insufficiente!")
        print("  👩 Alice: 'Oh no, devo ricaricare il wallet...'")
        return False

    print(f"  ✅ Addebitati {prezzo_euro:.2f}€ dal wallet di Alice")
    print(f"  👛 Nuovo saldo Alice: {alice_wallet.get_balance() / 100:.2f}€")

    # --- FASE 4: Accredito a Bob ---
    print("\n💵 Accredito in corso sulla cassa di Bob...")
    successo_credit = bob_pos.credit(prezzo_caffe)

    if not successo_credit:
        print("  ❌ Errore nell'accredito!")
        return False

    print(f"  ✅ Accreditati {prezzo_euro:.2f}€ sulla cassa di Bob")
    print(f"  🏦 Nuovo saldo Bob: {bob_pos.get_balance() / 100:.2f}€")

    # --- FASE 5: Firma digitale (la "ricevuta" crittografica) ---
    print("\n🔏 Generazione ricevuta digitale firmata...")
    timestamp = int(time.time())
    contatore = alice_wallet.get_counter()

    # Dati della transazione da firmare
    dati_transazione = struct.pack('>IIQ', prezzo_caffe, contatore, timestamp)
    firma = alice_wallet.sign_transaction(dati_transazione)

    print(f"  📝 Transazione firmata con ECDSA (firma: {len(firma)} byte)")
    print(f"  🔢 Contatore Alice: {contatore} (anti-replay)")

    # --- FASE 6: Verifica della firma ---
    print("\n🔍 Bob verifica la firma di Alice...")
    chiave_pubblica_alice = alice_wallet.get_certificate()
    firma_valida = bob_pos.verify_signature(dati_transazione, firma, chiave_pubblica_alice)

    if firma_valida:
        print("  ✅ Firma verificata! Pagamento autentico.")
        print("  👨 Bob: 'Perfetto! Ecco il tuo caffè ☕'")
    else:
        print("  ❌ ATTENZIONE: Firma non valida!")
        print("  👨 Bob: 'C'è un problema con il pagamento...'")
        return False

    # --- FASE 7: Preparazione per la riconciliazione ---
    print("\n📦 Preparazione per riconciliazione on-chain...")
    bridge = ReconciliationBridge()

    tx_data = {
        "sender_id": "alice_wallet_roma_001",
        "receiver_id": "bob_pos_bar_roma_001",
        "amount": prezzo_caffe,
        "counter": contatore,
        "signature": firma.hex(),
        "timestamp": timestamp
    }

    bridge.add_transaction(tx_data)
    print("  📬 Transazione accodata per la riconciliazione")
    print("     (verrà sincronizzata con la blockchain AEGIS")
    print("      quando il Wi-Fi del bar tornerà a funzionare 😄)")

    # --- Riepilogo finale ---
    print(f"\n{'🎉' * 20}")
    print(f"  PAGAMENTO COMPLETATO CON SUCCESSO!")
    print(f"{'🎉' * 20}")
    print(f"""
    📊 Riepilogo della transazione:
    ┌─────────────────────────────────────────┐
    │  👩 Alice                               │
    │     Pagato: {prezzo_euro:.2f}€                       │
    │     Saldo: {alice_wallet.get_balance() / 100:.2f}€ (prima: 100.00€)     │
    │                                         │
    │  👨 Bob                                 │
    │     Ricevuto: {prezzo_euro:.2f}€                     │
    │     Saldo: {bob_pos.get_balance() / 100:.2f}€ (prima: 200.00€)    │
    │                                         │
    │  🔏 Firma: valida ✅                     │
    │  🔢 Contatore: {contatore}                         │
    │  ⏰ Timestamp: {timestamp}            │
    │  📶 Connessione: OFFLINE               │
    └─────────────────────────────────────────┘
    """)

    print("👩 Alice se ne va con il suo caffè, soddisfatta.")
    print("👨 Bob sorride: 'AEGIS funziona anche senza internet!'\n")

    return True


# =============================================================================
# PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  AEGIS OFFLINE PAYMENTS — Esempio: Scenario Caffè")
    print("  Un pagamento offline nel mondo reale")
    print("=" * 60)

    successo = scenario_caffe()

    if successo:
        print("✅ Lo scenario si è concluso con successo!")
    else:
        print("❌ Lo scenario ha incontrato un errore.")
        sys.exit(1)
