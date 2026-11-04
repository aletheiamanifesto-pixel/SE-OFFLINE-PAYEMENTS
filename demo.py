"""
demo.py — Demo completa del pagamento offline AEGIS (protocollo v2)

Una giornata in una mini-rete di pagamento:
  Emittente (online)  ·  il tuo telefono  ·  il POS del bar  ·  il POS dell'edicola

Scenari:
  1. ONLINE   carichi denaro dal conto al chip
  2. OFFLINE  paghi un caffè con un tap NFC
  3. OFFLINE  sei attacchi che il chip blocca da solo
  4. OFFLINE  la connessione NFC si interrompe a metà: il denaro non si perde
  5. OFFLINE  un chip clonato spende due volte (il limite dell'offline)
  6. ONLINE   riconciliazione: la frode viene scoperta e il chip revocato
  7. ONLINE   il bar versa l'incasso sul conto, bilancio finale

Esecuzione:
    python demo.py            tutto di fila
    python demo.py --passo    pausa tra uno scenario e l'altro

Esce con codice 1 se un controllo non dà il risultato atteso (usato dalla CI).
"""

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bridge.emittente import Emittente, OperazioneRifiutata
from host_app.python import protocollo_v2 as v2
from host_app.python.pagamento_v2 import (
    ConnessioneInterrotta, ErroreProtocollo, TerminalePOS, consegna_pagamento,
    richiedi_pagamento,
)
from host_app.python.se_simulator import SecureElementSimulator

PASSO = "--passo" in sys.argv
controlli_falliti = 0


def euro(cent: int) -> str:
    return f"{cent / 100:,.2f} €".replace(",", "X").replace(".", ",").replace("X", ".")


def scenario(titolo: str, spiegazione: str) -> None:
    if PASSO:
        input("\n   [Invio per continuare] ")
    print(f"\n{'=' * 72}\n {titolo}\n{'=' * 72}")
    print(f" {spiegazione}\n")


def prova(descrizione: str, azione, atteso_ok: bool) -> None:
    """Esegue un'azione e verifica che vada (o non vada) a buon fine come previsto."""
    global controlli_falliti
    try:
        azione()
        esito, ok = "OK      ", True
        dettaglio = ""
    except (ErroreProtocollo, OperazioneRifiutata, ConnessioneInterrotta) as e:
        esito, ok = "RIFIUTO ", False
        dettaglio = f"  ->  {e}"
    segno = "✅" if ok == atteso_ok else "⚠️ INATTESO"
    if ok != atteso_ok:
        controlli_falliti += 1
    print(f"   {segno} {esito}{descrizione}{dettaglio}")


def saldi(*chip: tuple[str, SecureElementSimulator]) -> None:
    for nome, se in chip:
        print(f"      {nome:<24} {se.device_id.hex()}   saldo chip: {euro(se.get_balance()):>10}")


def clona_chip(originale: SecureElementSimulator) -> SecureElementSimulator:
    """ATTACCO: simula l'estrazione fisica della chiave privata da un chip violato."""
    clone = SecureElementSimulator()
    clone.__dict__.update({k: copy.copy(v) for k, v in originale.__dict__.items()})
    return clone


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print("\n AEGIS OFFLINE PAYMENTS — demo del protocollo v2")
    print(" Tutto gira in locale: chip simulati con ECDSA P-256 reale e comandi APDU.")

    emittente = Emittente()
    emittente.apri_conto("IT-TU", 1_000_00)
    emittente.apri_conto("IT-BAR", 0)

    tu = SecureElementSimulator()
    chip_bar = SecureElementSimulator()
    chip_edicola = SecureElementSimulator()
    emittente.personalizza(tu, "Tu (telefono)")
    emittente.personalizza(chip_bar, "Bar (POS)")
    emittente.personalizza(chip_edicola, "Edicola (POS)")
    bar = TerminalePOS(chip_bar, "Bar")
    edicola = TerminalePOS(chip_edicola, "Edicola")

    # ------------------------------------------------------------------ 1
    scenario("1. ONLINE — carichi 50 € dal conto al chip del telefono",
             "L'Emittente firma un ordine LOAD: solo così il denaro può entrare nel chip.")
    prova("carica 50,00 €", lambda: emittente.carica("IT-TU", tu, 50_00), True)
    prova("carica 400,00 € (oltre il limite di detenzione di 300 €)",
          lambda: emittente.carica("IT-TU", tu, 400_00), False)
    saldi(("Tu (telefono)", tu))
    print(f"      Conto IT-TU: {euro(emittente.conti['IT-TU'])}")

    # ------------------------------------------------------------------ 2
    scenario("2. OFFLINE — paghi un caffè al bar (nessuna connessione internet)",
             "Il tuo chip scala 1,50 €, aumenta il contatore e firma il token in un colpo solo.")
    caffe = bar.incassa(tu, 1_50)
    t = caffe.token
    print(f"      Pacchetto NFC: {v2.PACCHETTO_LEN} byte  (token {v2.TOKEN_LEN} + firma "
          f"{v2.SIG_LEN} + certificato {v2.CERT_LEN})")
    print(f"      Token: da {t.payer_id.hex()} a {t.payee_id.hex()}, "
          f"importo {euro(t.importo)}, contatore {t.contatore}")
    saldi(("Tu (telefono)", tu), ("Bar (POS)", chip_bar))

    # ------------------------------------------------------------------ 3
    scenario("3. OFFLINE — attacchi che il chip blocca da solo",
             "Nessuno di questi controlli ha bisogno della rete.")
    prova("il bar ripresenta lo stesso token (replay)", lambda: bar.ricevi(caffe), False)

    manomesso = v2.Pacchetto(v2.Token(t.payer_id, t.payee_id, 150_00, t.contatore + 10),
                             caffe.firma, caffe.certificato)
    prova("token manomesso: importo cambiato in 150 €", lambda: bar.ricevi(manomesso), False)
    prova("l'edicola prova a incassare il token del bar", lambda: edicola.ricevi(caffe), False)

    def stampa_soldi():
        risposta = chip_bar.process_apdu(bytes([0x80, 0x30, 0, 0, 4]) + (1_000_00).to_bytes(4, "big"))
        sw = int.from_bytes(risposta[-2:], "big")
        if sw != 0x9000:
            raise ErroreProtocollo(sw, "CREDIT v1")
    prova("il bar si auto-accredita 1.000 € con il vecchio CREDIT v1", stampa_soldi, False)

    falsario = Emittente("Emittente falso")
    chip_falso = SecureElementSimulator()
    falsario.personalizza(chip_falso, "Falsario")
    falsario.apri_conto("IT-FALSO", 1_000_00)
    falsario.carica("IT-FALSO", chip_falso, 100_00)
    prova("un chip certificato da un emittente falso paga il bar",
          lambda: bar.incassa(chip_falso, 20_00), False)
    prova("paghi 100 € avendone 48,50", lambda: bar.incassa(tu, 100_00), False)

    # ------------------------------------------------------------------ 4
    scenario("4. OFFLINE — il telefono si allontana a metà pagamento",
             "Il chip ha già scalato il saldo, ma il token non è arrivato al POS.")
    prova("paghi 3,00 € all'edicola (connessione interrotta)",
          lambda: edicola.incassa(tu, 3_00, interrompi_dopo_pay=True), False)
    saldi(("Tu (telefono)", tu), ("Edicola (POS)", chip_edicola))
    print("      -> Il token è rimasto salvato nel tuo chip. Secondo tap:")
    prova("l'edicola rilegge il token dal tuo chip e incassa",
          lambda: edicola.riprendi_pagamento_interrotto(tu), True)
    prova("l'edicola prova a rileggerlo di nuovo", lambda: edicola.riprendi_pagamento_interrotto(tu), False)
    saldi(("Tu (telefono)", tu), ("Edicola (POS)", chip_edicola))

    # ------------------------------------------------------------------ 5
    scenario("5. OFFLINE — chip violato e clonato: doppia spesa",
             "Un attaccante estrae la chiave dal tuo chip e ne fa una copia identica.")
    clone = clona_chip(tu)
    prova("il telefono vero paga 20 € al bar", lambda: bar.incassa(tu, 20_00), True)
    prova("il CLONE paga 20 € all'edicola", lambda: edicola.incassa(clone, 20_00), True)
    print("      -> Offline nessuno può accorgersene: i due POS non si parlano.")
    saldi(("Tu (telefono)", tu), ("Tu (CLONE)", clone), ("Bar (POS)", chip_bar),
          ("Edicola (POS)", chip_edicola))

    # ------------------------------------------------------------------ 6
    scenario("6. ONLINE — i POS si sincronizzano con l'Emittente",
             "L'Emittente vede lo stesso contatore usato per due token diversi.")
    for pos in (bar, edicola):
        r = emittente.sincronizza(pos.svuota_registro())
        print(f"      {pos.nome:<8} accettati {r.accettati}, duplicati {r.duplicati}, "
              f"non validi {r.non_validi}, doppie spese {len(r.doppie_spese)}")
        for d in r.doppie_spese:
            print(f"      !!! DOPPIA SPESA: chip {d.payer_id.hex()} contatore {d.contatore} "
                  f"usato verso {d.beneficiari[0].hex()} e {d.beneficiari[1].hex()}")
    print(f"      Chip revocati: {[emittente.titolare(c) for c in emittente.revocati]}"
          f"   perdita da coprire: {euro(emittente.perdite)}")

    prova("il bar (lista revoche VECCHIA) incassa 1 € dal chip clonato",
          lambda: bar.incassa(clone, 1_00), True)
    for pos in (bar, edicola):
        emittente.distribuisci_revoche(pos.chip)
    print("      -> I POS scaricano la lista revoche aggiornata.")
    prova("il clone riprova a pagare 1 € al bar", lambda: bar.incassa(clone, 1_00), False)
    prova("il titolare del chip revocato prova a ricaricarlo",
          lambda: emittente.carica("IT-TU", tu, 10_00), False)

    # ------------------------------------------------------------------ 7
    scenario("7. ONLINE — il bar versa l'incasso sul conto",
             "Lo scarico è firmato dall'Emittente e confermato dal chip del bar.")
    r = emittente.sincronizza(bar.svuota_registro())
    print(f"      Bar: {r.da_revocati} pagamento da chip revocato -> contato come perdita")
    incasso = chip_bar.get_balance()
    prova(f"scarica {euro(incasso)} su IT-BAR", lambda: emittente.scarica(chip_bar, "IT-BAR", incasso), True)
    saldi(("Bar (POS)", chip_bar))
    print(f"      Conto IT-BAR: {euro(emittente.conti['IT-BAR'])}")

    chip_onesti = tu.get_balance() + chip_bar.get_balance() + chip_edicola.get_balance()
    print("\n   BILANCIO DELL'EMITTENTE")
    print(f"      Caricato sui chip:            {euro(emittente.totale_caricato):>10}")
    print(f"      Scaricato sui conti:          {euro(emittente.totale_scaricato):>10}")
    print(f"      In circolazione (garantito):  {euro(emittente.in_circolazione()):>10}")
    print(f"      Perdita da frode (clone):     {euro(emittente.perdite):>10}")
    print(f"      Saldi dei chip legittimi:     {euro(chip_onesti):>10}")
    print("      (il saldo del chip revocato resta congelato fino alla verifica dell'Emittente)")

    def quadratura():
        if chip_onesti != emittente.in_circolazione() + emittente.perdite:
            raise OperazioneRifiutata("i conti non tornano")
    prova("saldi dei chip = denaro garantito + perdite da frode", quadratura, True)

    print(f"\n{'=' * 72}")
    if controlli_falliti:
        print(f" ⚠️  {controlli_falliti} controlli NON hanno dato il risultato atteso.")
        return 1
    print(" ✅ Tutti i controlli hanno dato il risultato atteso.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
