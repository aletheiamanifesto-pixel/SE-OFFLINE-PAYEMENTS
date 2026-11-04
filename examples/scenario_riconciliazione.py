"""
scenario_riconciliazione.py — Esempio end-to-end: pagamenti offline → riconciliazione on-chain

Questo scenario dimostrativo mostra l'intero ciclo di vita di un pagamento
con il sistema AEGIS integrato con aegis-protocol:

  1. 📱 Esecuzione di pagamenti offline tra Alice e Bob (come scenario_caffe.py)
  2. 📦 Accumulo delle transazioni nel ReconciliationBridge
  3. 🔌 Connessione ad aegis-protocol (o modalità mock se non disponibile)
  4. 🔄 Riconciliazione di tutte le TX pendenti on-chain
  5. ✅ Verifica dello stato on-chain per ogni TX
  6. 📊 Riepilogo finale con tx_hash

Esecuzione:
    python examples/scenario_riconciliazione.py

Con aegis-protocol in esecuzione:
    AEGIS_URL=http://localhost:8000 python examples/scenario_riconciliazione.py

Modalità mock (default se aegis-protocol non è raggiungibile):
    Il sistema usa risposte simulate per dimostrare il flusso senza blockchain.
"""

import os
import struct
import sys
import time
from pathlib import Path

# Permette di lanciare lo script direttamente (python examples/...) senza pip install
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from host_app.python.se_simulator import SecureElementSimulator
from bridge.aegis_client import AegisClient
from bridge.aegis_reconciler import AegisReconciler
from bridge.identity_mapper import IdentityMapper
from bridge.zk_proof_adapter import ZkProofAdapter


# =============================================================================
# CONFIGURAZIONE SCENARIO
# =============================================================================

# URL dell'API aegis-protocol (modificabile via variabile d'ambiente)
AEGIS_API_URL = os.environ.get("AEGIS_URL", "http://localhost:8000")

# Percorso del registry dispositivi (temporaneo per questo esempio)
REGISTRY_PATH = "/tmp/aegis_demo_registry.json"


def _intestazione(titolo: str, simbolo: str = "═") -> None:
    """Stampa un'intestazione formattata."""
    linea = simbolo * 60
    print(f"\n{linea}")
    print(f"  {titolo}")
    print(linea)


def _sezione(titolo: str) -> None:
    """Stampa un'intestazione di sezione."""
    print(f"\n{'─' * 50}")
    print(f"  {titolo}")
    print('─' * 50)


# =============================================================================
# FASE 1: CONFIGURAZIONE DEI DISPOSITIVI
# =============================================================================

def fase_1_setup() -> tuple:
    """
    Inizializza i Secure Element e registra i dispositivi nel registry.

    Simula la fase di onboarding: Alice e Bob si registrano al sistema,
    associando i loro chip NFC agli indirizzi wallet Ethereum on-chain.

    Ritorna:
        Tupla (alice_se, bob_se, mapper) con i simulatori e il registry
    """
    _sezione("FASE 1: Setup dispositivi e identità")

    # Indirizzi wallet Ethereum simulati (in produzione: generati da aegis-protocol)
    alice_wallet = "0xA1ce0000000000000000000000000000000001ce"
    bob_wallet = "0xB0b00000000000000000000000000000000000b0"

    # Inizializzazione Secure Element simulati
    alice_se = SecureElementSimulator(initial_balance=50000)  # 500.00€
    bob_se = SecureElementSimulator(initial_balance=20000)    # 200.00€

    # Ottieni le chiavi pubbliche (65 byte = punto non compresso secp256r1)
    alice_pubkey = alice_se.get_certificate().hex()
    bob_pubkey = bob_se.get_certificate().hex()

    # Registry dispositivi SE ↔ wallet on-chain
    mapper = IdentityMapper(registry_path=REGISTRY_PATH)

    # Registra i dispositivi (sovrascriviamo se già esistono per idempotenza)
    mapper.register_device(
        se_device_id="alice_wallet_roma_001",
        wallet_address=alice_wallet,
        public_key=alice_pubkey,
        metadata={"nome": "Alice Rossi", "città": "Roma"},
        overwrite=True,
    )
    mapper.register_device(
        se_device_id="bob_pos_bar_roma_001",
        wallet_address=bob_wallet,
        public_key=bob_pubkey,
        metadata={"nome": "Bar Di Bob", "città": "Roma"},
        overwrite=True,
    )

    print(f"  👩 Alice — SE: alice_wallet_roma_001")
    print(f"             Wallet: {alice_wallet}")
    print(f"             Saldo SE: {alice_se.get_balance() / 100:.2f}€")
    print()
    print(f"  👨 Bob   — SE: bob_pos_bar_roma_001")
    print(f"             Wallet: {bob_wallet}")
    print(f"             Saldo SE: {bob_se.get_balance() / 100:.2f}€")
    print()
    print(f"  📋 Registry: {mapper.count()} dispositivi registrati")

    return alice_se, bob_se, mapper


# =============================================================================
# FASE 2: PAGAMENTI OFFLINE
# =============================================================================

def fase_2_pagamenti_offline(alice_se: SecureElementSimulator,
                              bob_se: SecureElementSimulator) -> list[dict]:
    """
    Esegue una serie di pagamenti offline tra Alice e Bob.

    Simula la giornata al bar: Alice paga più volte, Bob accumula incassi.
    Tutto avviene offline, senza internet.

    Parametri:
        alice_se: Secure Element simulato di Alice
        bob_se: Secure Element simulato di Bob

    Ritorna:
        Lista di dizionari transazione pronti per la riconciliazione
    """
    _sezione("FASE 2: Pagamenti offline (senza internet)")

    # Selezione applet su entrambi i dispositivi
    apdu_select = SecureElementSimulator.build_apdu(0x00, 0xA4)
    alice_se.process_apdu(apdu_select)
    bob_se.process_apdu(apdu_select)

    # Lista pagamenti della giornata
    pagamenti = [
        {"descrizione": "☕ Caffè mattutino",          "importo": 120},   # 1.20€
        {"descrizione": "🥐 Cornetto e succo",         "importo": 280},   # 2.80€
        {"descrizione": "🍕 Pranzo veloce",            "importo": 850},   # 8.50€
        {"descrizione": "🍺 Aperitivo serale",         "importo": 950},   # 9.50€
    ]

    transazioni = []

    print("  🌐 Wi-Fi del bar: SPENTO (come sempre!)")
    print("  💳 Pagamenti NFC offline in corso...\n")

    for pagamento in pagamenti:
        importo = pagamento["importo"]
        descrizione = pagamento["descrizione"]

        # Verifica saldo Alice
        if alice_se.get_balance() < importo:
            print(f"  ❌ {descrizione}: saldo insufficiente (saltato)")
            continue

        # Addebito Alice
        if not alice_se.debit(importo):
            print(f"  ❌ {descrizione}: errore addebito (saltato)")
            continue

        # Accredito Bob
        bob_se.credit(importo)

        # Firma ECDSA della transazione
        timestamp = int(time.time())
        contatore = alice_se.get_counter()
        dati_da_firmare = struct.pack('>IIQ', importo, contatore, timestamp)
        firma = alice_se.sign_transaction(dati_da_firmare)

        # Verifica firma (Bob verifica che Alice abbia firmato davvero)
        chiave_pub_alice = alice_se.get_certificate()
        if not bob_se.verify_signature(dati_da_firmare, firma, chiave_pub_alice):
            print(f"  ❌ {descrizione}: firma non valida (saltato)")
            alice_se.credit(importo)  # Storno
            continue

        # Transazione pronta per la riconciliazione
        tx = {
            "sender_id": "alice_wallet_roma_001",
            "receiver_id": "bob_pos_bar_roma_001",
            "amount": importo,
            "counter": contatore,
            "signature": firma.hex(),
            "timestamp": float(timestamp),
            "descrizione": descrizione,
        }
        transazioni.append(tx)

        print(f"  ✅ {descrizione}: {importo / 100:.2f}€ "
              f"(ctr={contatore}, sig={firma.hex()[:16]}...)")

    print(f"\n  📊 Totale transazioni offline: {len(transazioni)}")
    print(f"  💰 Importo totale: {sum(t['amount'] for t in transazioni) / 100:.2f}€")
    print(f"  👛 Saldo Alice rimasto: {alice_se.get_balance() / 100:.2f}€")
    print(f"  🏦 Saldo Bob accumulato: {bob_se.get_balance() / 100:.2f}€")

    return transazioni


# =============================================================================
# FASE 3: RICONCILIAZIONE ON-CHAIN
# =============================================================================

def fase_3_riconciliazione(transazioni: list[dict],
                            mapper: IdentityMapper) -> dict:
    """
    Riconcilia le transazioni offline on-chain tramite aegis-protocol.

    Simula il momento in cui il Wi-Fi torna online e il sistema
    sincronizza tutte le transazioni della giornata con la blockchain.

    Parametri:
        transazioni: lista di transazioni offline da riconciliare
        mapper: registry dispositivi SE ↔ wallet on-chain

    Ritorna:
        Risultato della riconciliazione con tx_hash on-chain
    """
    _sezione("FASE 3: Connessione ad aegis-protocol e riconciliazione")

    # Inizializzazione client aegis-protocol
    client = AegisClient(
        base_url=AEGIS_API_URL,
        username="demo_bridge",
        password="demo_secret",
        mock_mode=False,  # Prima tentiamo la connessione reale
    )

    # Test di connettività
    print(f"  🔌 Tentativo connessione a: {AEGIS_API_URL}")
    if client.ping():
        print(f"  ✅ aegis-protocol raggiungibile — modalità LIVE")
    else:
        print(f"  ⚠️  aegis-protocol non raggiungibile — attivazione modalità MOCK")
        client.enable_mock_mode()
        print(f"  🔄 Riconciliazione simulata attiva")

    # Inizializzazione riconciliatore
    zk_adapter = ZkProofAdapter(enable_local_verification=True)
    reconciler = AegisReconciler(
        aegis_client=client,
        identity_mapper=mapper,
        zk_adapter=zk_adapter,
        fallback_to_simulated=True,
    )

    # Registra le chiavi pubbliche nel bridge per verifica ECDSA
    for device in mapper.list_devices():
        pub_key_bytes = bytes.fromhex(device["public_key"])
        reconciler.register_public_key(device["se_device_id"], pub_key_bytes)

    # Accodiamo le transazioni nel bridge
    print(f"\n  📬 Accodamento {len(transazioni)} transazioni nel bridge...")
    for tx in transazioni:
        # Rimuoviamo il campo 'descrizione' non standard prima di aggiungere
        tx_senza_desc = {k: v for k, v in tx.items() if k != "descrizione"}
        reconciler.add_transaction(tx_senza_desc)

    print(f"  📥 Transazioni pendenti: {len(reconciler.get_pending_transactions())}")

    # Esecuzione della riconciliazione
    print(f"\n  🔄 Avvio riconciliazione...")
    risultato = reconciler.reconcile()

    return risultato


# =============================================================================
# FASE 4: VERIFICA STATO ON-CHAIN
# =============================================================================

def fase_4_verifica_onchain(risultato: dict, client: AegisClient) -> None:
    """
    Verifica lo stato on-chain per ogni transazione riconciliata.

    Parametri:
        risultato: risultato della riconciliazione
        client: client HTTP aegis-protocol
    """
    _sezione("FASE 4: Verifica stato on-chain")

    tx_ok = risultato.get("transazioni_ok", [])
    if not tx_ok:
        print("  ℹ️  Nessuna transazione da verificare")
        return

    for tx_info in tx_ok:
        tx_hash = tx_info.get("tx_hash", "N/A")
        try:
            status = client.get_transaction_status(tx_hash)
            print(f"  🔗 TX: {tx_hash[:20]}...")
            print(f"     Stato: {status.get('status', 'unknown')}")
            print(f"     Blocco: {status.get('block_number', 'N/A')}")
            print(f"     Conferme: {status.get('confirmations', 'N/A')}")
        except Exception as exc:
            print(f"  ⚠️  Impossibile verificare TX {tx_hash[:20]}...: {exc}")


# =============================================================================
# RIEPILOGO FINALE
# =============================================================================

def riepilogo_finale(transazioni: list[dict], risultato: dict) -> None:
    """Stampa il riepilogo completo dello scenario."""
    _sezione("RIEPILOGO FINALE")

    totale_importo = sum(t["amount"] for t in transazioni) / 100.0
    successi = risultato.get("successi", 0)
    fallimenti = risultato.get("fallimenti", 0)
    strappate = len(risultato.get("transazioni_strappate", []))
    durata = risultato.get("durata_secondi", 0)

    print(f"""
  📊 Statistiche riconciliazione:
  ┌──────────────────────────────────────────────┐
  │  Transazioni totali:    {risultato.get('totale', 0):<5}                   │
  │  Riconciliate OK:       {successi:<5}  ✅                │
  │  Fallite:               {fallimenti:<5}  ❌                │
  │  Strappate (retry):     {strappate:<5}  ⚠️               │
  │                                              │
  │  Importo totale:        {totale_importo:<8.2f}€              │
  │  Durata riconciliazione: {durata:<6.1f}s              │
  └──────────────────────────────────────────────┘""")

    if risultato.get("transazioni_ok"):
        print("\n  📋 TX on-chain:")
        for tx_info in risultato["transazioni_ok"]:
            tx_hash = tx_info.get("tx_hash", "N/A")
            importo = tx_info.get("amount", 0) / 100.0
            print(f"    {importo:.2f}€ → {tx_hash}")

    if strappate > 0:
        print(f"\n  ⚠️  {strappate} transazioni 'strappate' richiedono intervento manuale.")
        print("     (Il debit offline è avvenuto ma il credit on-chain è fallito)")

    modo = "LIVE (blockchain reale)" if not risultato.get("transazioni_ok", [{}])[0].get(
        "status", ""
    ).startswith("mock") else "MOCK (simulato)"
    print(f"\n  🔧 Modalità: {modo}")


# =============================================================================
# PUNTO DI INGRESSO PRINCIPALE
# =============================================================================

def scenario_riconciliazione() -> bool:
    """
    Esegue lo scenario completo di riconciliazione end-to-end.

    Ritorna:
        True se lo scenario è completato con successo, False altrimenti
    """
    _intestazione("AEGIS OFFLINE PAYMENTS — Scenario Riconciliazione", "═")
    print("""
  Questo scenario dimostra il ciclo completo:
  1. Alice paga al bar di Bob (offline, senza internet)
  2. Le transazioni vengono accumulate nel bridge
  3. Quando il Wi-Fi torna, si riconcilia tutto on-chain
  4. aegis-protocol registra ogni TX su Polygon Amoy (AegisEUR.sol)
    """)

    try:
        # Fase 1: Setup
        alice_se, bob_se, mapper = fase_1_setup()

        # Fase 2: Pagamenti offline
        transazioni = fase_2_pagamenti_offline(alice_se, bob_se)

        if not transazioni:
            print("\n❌ Nessuna transazione generata. Scenario interrotto.")
            return False

        # Fase 3: Riconciliazione
        risultato = fase_3_riconciliazione(transazioni, mapper)

        # Fase 4: Verifica on-chain
        client = AegisClient(base_url=AEGIS_API_URL, mock_mode=True)
        fase_4_verifica_onchain(risultato, client)

        # Riepilogo
        riepilogo_finale(transazioni, risultato)

        print("\n✅ Scenario completato con successo!")
        return True

    except KeyboardInterrupt:
        print("\n\n⚠️  Scenario interrotto dall'utente.")
        return False
    except Exception as exc:
        print(f"\n❌ Errore nello scenario: {exc}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    successo = scenario_riconciliazione()

    if not successo:
        import sys
        sys.exit(1)
