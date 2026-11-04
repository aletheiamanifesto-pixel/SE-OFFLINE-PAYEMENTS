"""
payment_flow.py — Flusso di pagamento offline completo tra due Secure Element

Immagina di essere al mercato rionale: Alice vuole comprare qualcosa da Bob.
Nessuno dei due ha connessione internet, ma entrambi hanno il loro telefono
con il chip NFC (Secure Element) caricato con token AEGIS Euro.

Il pagamento avviene così, proprio come con i contanti:
1. Alice e Bob "tirano fuori il portafoglio" (SELECT applet)
2. Controllano quanto hanno (GET_BALANCE)
3. Alice toglie i soldi dal suo portafoglio (DEBIT)
4. Bob li mette nel suo (CREDIT)
5. Alice firma una "ricevuta digitale" (SIGN) che prova il pagamento
6. Bob verifica che la firma sia autentica (VERIFY)
7. Entrambi aggiornano il contatore (come staccare lo scontrino)

Tutto questo avviene OFFLINE, senza bisogno di una banca o di internet.
La riconciliazione con la blockchain AEGIS avviene dopo, quando c'è connessione.
"""

import struct
import sys
import time
from pathlib import Path

# Permette di lanciare lo script direttamente (python host_app/...) senza pip install
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from host_app.python.se_simulator import SecureElementSimulator


def esegui_pagamento(pagatore: SecureElementSimulator,
                     ricevente: SecureElementSimulator,
                     importo_centesimi: int) -> bool:
    """
    Esegue un pagamento offline completo tra due Secure Element.

    È come una stretta di mano commerciale tra due persone al mercato:
    1. Si presentano (SELECT)
    2. Controllano i portafogli (GET_BALANCE)
    3. Il pagatore sgancia i soldi (DEBIT)
    4. Il ricevente li incassa (CREDIT)
    5. Il pagatore firma la ricevuta (SIGN)
    6. Il ricevente verifica la firma (VERIFY)

    Parametri:
        pagatore: il SecureElementSimulator di chi paga
        ricevente: il SecureElementSimulator di chi riceve
        importo_centesimi: l'importo in centesimi (es. 2500 = 25.00€)

    Ritorna:
        True se il pagamento è andato a buon fine, False altrimenti
    """
    importo_euro = importo_centesimi / 100.0

    print("\n" + "=" * 60)
    print(f"  💶 PAGAMENTO OFFLINE AEGIS — {importo_euro:.2f}€")
    print("=" * 60)

    # --- FASE 1: Selezione applet (come inserire la carta nel POS) ---
    print("\n📱 FASE 1: Selezione applet su entrambi i dispositivi...")
    apdu_select = SecureElementSimulator.build_apdu(0x00, 0xA4)

    resp_pagatore = pagatore.process_apdu(apdu_select)
    resp_ricevente = ricevente.process_apdu(apdu_select)

    if _estrai_sw(resp_pagatore) != 0x9000 or _estrai_sw(resp_ricevente) != 0x9000:
        print("  ❌ Errore nella selezione dell'applet!")
        return False
    print("  ✅ Applet selezionato su entrambi i dispositivi")

    # --- FASE 2: Controllo saldi (come guardare nel portafoglio) ---
    print("\n💰 FASE 2: Verifica saldi correnti...")
    apdu_balance = SecureElementSimulator.build_apdu(0x80, 0x10)

    resp_saldo_pag = pagatore.process_apdu(apdu_balance)
    resp_saldo_ric = ricevente.process_apdu(apdu_balance)

    saldo_pagatore = struct.unpack('>I', resp_saldo_pag[:-2])[0]
    saldo_ricevente = struct.unpack('>I', resp_saldo_ric[:-2])[0]

    print(f"  👛 Pagatore: {saldo_pagatore / 100:.2f}€")
    print(f"  👛 Ricevente: {saldo_ricevente / 100:.2f}€")

    # Controllo preventivo: il pagatore ha abbastanza soldi?
    if saldo_pagatore < importo_centesimi:
        print(f"  ❌ Saldo insufficiente! Servono {importo_euro:.2f}€ "
              f"ma il pagatore ha solo {saldo_pagatore / 100:.2f}€")
        return False

    # --- FASE 3: Addebito sul pagatore (come togliere i soldi dal portafoglio) ---
    print(f"\n💸 FASE 3: Addebito di {importo_euro:.2f}€ dal pagatore...")
    data_importo = struct.pack('>I', importo_centesimi)
    apdu_debit = SecureElementSimulator.build_apdu(0x80, 0x20, data=data_importo)

    resp_debit = pagatore.process_apdu(apdu_debit)
    if _estrai_sw(resp_debit) != 0x9000:
        print(f"  ❌ Addebito fallito! Codice errore: 0x{_estrai_sw(resp_debit):04X}")
        return False

    nuovo_saldo_pag = struct.unpack('>I', resp_debit[:-2])[0]
    print(f"  ✅ Addebito riuscito! Nuovo saldo pagatore: {nuovo_saldo_pag / 100:.2f}€")

    # --- FASE 4: Accredito sul ricevente (come mettere i soldi nel portafoglio) ---
    print(f"\n💵 FASE 4: Accredito di {importo_euro:.2f}€ al ricevente...")
    apdu_credit = SecureElementSimulator.build_apdu(0x80, 0x30, data=data_importo)

    resp_credit = ricevente.process_apdu(apdu_credit)
    if _estrai_sw(resp_credit) != 0x9000:
        print(f"  ❌ Accredito fallito! Codice errore: 0x{_estrai_sw(resp_credit):04X}")
        return False

    nuovo_saldo_ric = struct.unpack('>I', resp_credit[:-2])[0]
    print(f"  ✅ Accredito riuscito! Nuovo saldo ricevente: {nuovo_saldo_ric / 100:.2f}€")

    # --- FASE 5: Firma digitale della transazione ---
    # Il pagatore firma i dati della transazione come prova di autorizzazione.
    # È come firmare lo scontrino dopo aver pagato con la carta.
    print("\n🔏 FASE 5: Firma digitale della transazione...")
    timestamp = int(time.time())
    contatore_pagatore = pagatore.get_counter()

    # Dati da firmare: importo + contatore + timestamp
    # Così la firma è unica e non riutilizzabile (anti-replay)
    dati_transazione = struct.pack('>IIQ', importo_centesimi, contatore_pagatore, timestamp)

    apdu_sign = SecureElementSimulator.build_apdu(0x80, 0x50, data=dati_transazione)
    resp_sign = pagatore.process_apdu(apdu_sign)

    if _estrai_sw(resp_sign) != 0x9000:
        print("  ❌ Firma fallita!")
        return False

    firma = resp_sign[:-2]  # Togliamo lo status word
    print(f"  ✅ Transazione firmata ({len(firma)} byte di firma ECDSA)")

    # --- FASE 6: Verifica della firma ---
    # Il ricevente verifica che la firma sia autentica.
    # È come quando il negoziante controlla la firma sullo scontrino.
    print("\n🔍 FASE 6: Verifica della firma da parte del ricevente...")

    # Otteniamo la chiave pubblica del pagatore (il suo "documento d'identità")
    apdu_cert = SecureElementSimulator.build_apdu(0x80, 0x60)
    resp_cert = pagatore.process_apdu(apdu_cert)
    chiave_pubblica_pagatore = resp_cert[:-2]

    # Il ricevente verifica la firma usando la chiave pubblica del pagatore
    firma_valida = ricevente.verify_signature(dati_transazione, firma, chiave_pubblica_pagatore)

    if not firma_valida:
        print("  ❌ ATTENZIONE: Firma non valida! Possibile frode!")
        return False
    print("  ✅ Firma verificata con successo — transazione autentica!")

    # --- FASE 7: Contatori finali (come controllare il numero di scontrino) ---
    print("\n🔢 FASE 7: Verifica contatori monotònici...")
    apdu_counter = SecureElementSimulator.build_apdu(0x80, 0x40)

    resp_cnt_pag = pagatore.process_apdu(apdu_counter)
    resp_cnt_ric = ricevente.process_apdu(apdu_counter)

    cnt_pagatore = struct.unpack('>I', resp_cnt_pag[:-2])[0]
    cnt_ricevente = struct.unpack('>I', resp_cnt_ric[:-2])[0]

    print(f"  🔄 Contatore pagatore: {cnt_pagatore}")
    print(f"  🔄 Contatore ricevente: {cnt_ricevente}")

    # --- RIEPILOGO FINALE ---
    print("\n" + "=" * 60)
    print("  🎉 PAGAMENTO COMPLETATO CON SUCCESSO!")
    print("=" * 60)
    print(f"  📊 Riepilogo:")
    print(f"     Importo trasferito: {importo_euro:.2f}€")
    print(f"     Saldo pagatore:     {pagatore.get_balance() / 100:.2f}€")
    print(f"     Saldo ricevente:    {ricevente.get_balance() / 100:.2f}€")
    print(f"     Timestamp:          {timestamp}")
    print(f"     Firma valida:       ✅ Sì")
    print("=" * 60 + "\n")

    return True


def _estrai_sw(risposta: bytes) -> int:
    """
    Estrae la Status Word (ultimi 2 byte) dalla risposta APDU.

    La Status Word è come il semaforo alla fine dell'operazione:
      🟢 0x9000 = verde, tutto OK
      🔴 0x6985 = rosso, saldo insufficiente
      🟡 0x6700 = giallo, dati malformati
    """
    if len(risposta) < 2:
        return 0x6F00  # Errore generico
    return (risposta[-2] << 8) | risposta[-1]


# =============================================================================
# PUNTO DI INGRESSO — Esecuzione diretta dello script
# =============================================================================

if __name__ == "__main__":
    print("\n🏦 ═══════════════════════════════════════════════════════════")
    print("   AEGIS OFFLINE PAYMENT SYSTEM — Dimostrazione Completa")
    print("   Sistema di pagamento peer-to-peer offline con Secure Element")
    print("🏦 ═══════════════════════════════════════════════════════════\n")

    # --- Creazione dei due "portafogli digitali" ---
    # Alice ha 100.00€ (10000 centesimi) — come una carta prepagata appena caricata
    # Bob ha 50.00€ (5000 centesimi) — come un commerciante con il resto in cassa
    print("👤 Creazione Secure Element di Alice (saldo: 100.00€)...")
    alice_se = SecureElementSimulator(initial_balance=10000)

    print("👤 Creazione Secure Element di Bob (saldo: 50.00€)...")
    bob_se = SecureElementSimulator(initial_balance=5000)

    # --- Esecuzione del pagamento: Alice paga 25.00€ a Bob ---
    successo = esegui_pagamento(alice_se, bob_se, importo_centesimi=2500)

    if successo:
        print("✅ La dimostrazione è completata con successo!")
        print("   In un sistema reale, questa transazione verrebbe")
        print("   riconciliata con la blockchain AEGIS alla prossima connessione.\n")
    else:
        print("❌ La dimostrazione ha incontrato un errore.\n")
        sys.exit(1)
