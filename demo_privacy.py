"""
demo_privacy.py — Modalità privacy: monete con firma cieca (e-cash alla Chaum)

Stessa giornata della demo principale, ma il denaro sono MONETE anonime:
  1. ONLINE   prelevi 20 € in monete: l'Emittente le firma "alla cieca"
  2. OFFLINE  paghi un caffè: il bar verifica le monete senza rete
  3. OFFLINE  attacchi bloccati: moneta falsa, copia, destinatario sbagliato
  4. ONLINE   il bar deposita: l'Emittente paga ma NON sa chi ha speso
  5. OFFLINE  chip clonato: la stessa moneta spesa due volte
  6. ONLINE   doppia spesa scoperta: il Garante apre SOLO le buste di quella moneta
  7.          chi sa cosa: confronto tra modalità tracciabile e privata

Esecuzione:
    python demo_privacy.py            tutto di fila
    python demo_privacy.py --passo    pausa tra uno scenario e l'altro
"""

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bridge.ecash import (
    EmittentePrivato, Garante, Moneta, NegozioPrivato, PortafoglioPrivato, Spesa, euro,
)

PASSO = "--passo" in sys.argv
controlli_falliti = 0


def scenario(titolo: str, spiegazione: str) -> None:
    if PASSO:
        input("\n   [Invio per continuare] ")
    print(f"\n{'=' * 72}\n {titolo}\n{'=' * 72}")
    print(f" {spiegazione}\n")


def prova(descrizione: str, azione, atteso_ok: bool) -> None:
    global controlli_falliti
    try:
        azione()
        esito, ok, dettaglio = "OK      ", True, ""
    except ValueError as e:
        esito, ok, dettaglio = "RIFIUTO ", False, f"  ->  {e}"
    if ok != atteso_ok:
        controlli_falliti += 1
    print(f"   {'✅' if ok == atteso_ok else '⚠️ INATTESO'} {esito}{descrizione}{dettaglio}")


def verifica(descrizione: str, condizione: bool) -> None:
    def controllo():
        if not condizione:
            raise ValueError("condizione falsa")
    prova(descrizione, controllo, True)


def monete(lista) -> str:
    conteggio: dict[int, int] = {}
    for m in lista:
        conteggio[m.taglio] = conteggio.get(m.taglio, 0) + 1
    return " + ".join(f"{k}×{euro(t)}" if k > 1 else euro(t)
                      for t, k in sorted(conteggio.items(), reverse=True))


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print("\n AEGIS OFFLINE PAYMENTS — modalità privacy (firma cieca)")
    print(" Monete RSA con firma cieca + buste sigillate per un Garante indipendente.")
    print(" Generazione delle chiavi dell'Emittente e del Garante...")

    garante = Garante()
    emittente = EmittentePrivato(garante)
    emittente.apri_conto("IT-TU", 100_00)
    emittente.apri_conto("IT-BAR", 0)
    emittente.apri_conto("IT-EDICOLA", 0)
    chiavi, chiave_garante = emittente.chiavi_pubbliche, garante.chiave_pubblica

    tu = PortafoglioPrivato("chip di Tu", chiavi, chiave_garante)
    bar = NegozioPrivato("Bar", chiavi, chiave_garante)
    edicola = NegozioPrivato("Edicola", chiavi, chiave_garante)

    # ------------------------------------------------------------------ 1
    scenario("1. ONLINE — prelevi 20 € in monete anonime",
             "Il telefono genera numeri di serie casuali, li NASCONDE e li fa firmare.")
    n = tu.preleva(emittente, "IT-TU", 20_00)
    print(f"      {n} monete: {monete(tu.monete)}")
    print(f"      Conto IT-TU: {euro(emittente.conti['IT-TU'])}   saldo telefono: {euro(tu.saldo)}")
    print("      L'Emittente sa che hai prelevato 20 €, ma non conosce nessun numero di serie.")
    verifica("nessun numero di serie è tra i valori firmati dall'Emittente",
             not any(emittente.collega_al_prelievo(m) for m in tu.monete))

    # ------------------------------------------------------------------ 2
    scenario("2. OFFLINE — paghi un caffè da 1,50 €",
             "Il bar verifica la firma dell'Emittente su ogni moneta, senza rete.")
    caffe = tu.paga("Bar", 1_50)
    prova(f"il bar incassa {monete(s.moneta for s in caffe)}", lambda: bar.incassa(caffe), True)
    print(f"      Saldo telefono: {euro(tu.saldo)}   cassa bar: {euro(bar.saldo)}")
    print(f"      Ogni moneta viaggia con una busta sigillata per il Garante ({len(caffe[0].busta)} byte):")
    print("      il bar non può aprirla, quindi non sa chi sei.")

    # ------------------------------------------------------------------ 3
    scenario("3. OFFLINE — attacchi bloccati dal POS",
             "Tutti i controlli usano solo le chiavi pubbliche dell'Emittente.")
    vera = caffe[0].moneta
    falsa = Spesa(Moneta(200, b"\x01" * 32, vera.firma), "Bar", caffe[0].busta)
    prova("moneta da 2 € con firma inventata", lambda: bar.incassa([falsa]), False)
    prova("il bar ripresenta la stessa moneta", lambda: bar.incassa([caffe[0]]), False)
    prova("l'edicola prova a incassare le monete del bar", lambda: edicola.incassa(caffe), False)
    prova("paghi 50 € avendone 18,50", lambda: tu.paga("Bar", 50_00), False)

    # ------------------------------------------------------------------ 4
    scenario("4. ONLINE — il bar deposita l'incasso",
             "L'Emittente riconosce le proprie firme e paga, ma non può collegarle al prelievo.")
    esito = bar.deposita(emittente, "IT-BAR")
    print(f"      Accreditati {euro(esito.accreditato)} su IT-BAR")
    verifica("l'Emittente NON riesce a collegare le monete del caffè al tuo prelievo",
             not any(emittente.collega_al_prelievo(s.moneta) for s in caffe))
    verifica("il Garante non ha aperto nessuna busta", garante.buste_aperte == 0)

    # ------------------------------------------------------------------ 5
    scenario("5. OFFLINE — chip violato e clonato",
             "Un attaccante copia le monete del tuo chip e spende la stessa moneta due volte.")
    clone = copy.copy(tu)
    clone.monete = list(tu.monete)
    al_bar = tu.paga("Bar", 2_00)
    all_edicola = clone.paga("Edicola", 2_00)
    print(f"      Moneta usata due volte: {al_bar[0].moneta.id_breve}… "
          f"(stessa di {all_edicola[0].moneta.id_breve}…)")
    prova("il telefono vero paga 2 € al bar", lambda: bar.incassa(al_bar), True)
    prova("il CLONE paga la stessa moneta all'edicola", lambda: edicola.incassa(all_edicola), True)
    print("      -> Offline nessuno può accorgersene: bar ed edicola non si parlano.")

    # ------------------------------------------------------------------ 6
    scenario("6. ONLINE — depositi: la doppia spesa viene scoperta",
             "L'Emittente non paga due volte la stessa moneta e chiama il Garante.")
    print(f"      Bar:     accreditati {euro(bar.deposita(emittente, 'IT-BAR').accreditato)}")
    esito = edicola.deposita(emittente, "IT-EDICOLA")
    print(f"      Edicola: accreditati {euro(esito.accreditato)}, "
          f"doppie spese bloccate {len(esito.doppie_spese)}")
    for prima, seconda in esito.doppie_spese:
        chi_1, _ = garante.apri(prima.busta)
        chi_2, _ = garante.apri(seconda.busta)
        print(f"      !!! Moneta {prima.moneta.id_breve}… spesa da Bar e Edicola: "
              f"il Garante apre le 2 buste -> '{chi_1}' / '{chi_2}'")
        verifica("le due buste identificano lo stesso chip", chi_1 == chi_2 == "chip di Tu")
    verifica("il Garante ha aperto solo le 2 buste della moneta duplicata", garante.buste_aperte == 2)
    print("      Le buste del caffè e di tutti i pagamenti onesti restano sigillate.")
    print("      L'edicola non viene pagata per quella moneta e può rivalersi sul colpevole.")

    # ------------------------------------------------------------------ 7
    scenario("7. Chi sa cosa: modalità tracciabile (demo.py) e privata (questa demo)",
             "Il prezzo della privacy: l'hardware deve impedire le copie, la crittografia le scopre dopo.")
    righe = [
        ("Chi preleva e quanto", "Emittente", "Emittente"),
        ("Chi incassa e quanto", "Emittente", "Emittente"),
        ("Chi ha pagato chi", "Emittente (sempre)", "nessuno"),
        ("Chi ha fatto doppia spesa", "Emittente", "Garante, solo per quella moneta"),
        ("Il negozio sa chi sei?", "sì (id del chip)", "no"),
    ]
    print(f"      {'':<28}{'Tracciabile':<22}Privata")
    for domanda, tracciabile, privata in righe:
        print(f"      {domanda:<28}{tracciabile:<22}{privata}")

    print(f"\n{'=' * 72}")
    if controlli_falliti:
        print(f" ⚠️  {controlli_falliti} controlli NON hanno dato il risultato atteso.")
        return 1
    print(" ✅ Tutti i controlli hanno dato il risultato atteso.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
