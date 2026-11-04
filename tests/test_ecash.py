"""
test_ecash.py — Test della modalità privacy (monete con firma cieca)
"""

import copy

import pytest

from bridge.ecash import (
    TAGLI, EmittentePrivato, Garante, Moneta, NegozioPrivato, PortafoglioPrivato, Spesa,
    componi_prelievo, scegli_monete,
)


@pytest.fixture(scope="module")
def chiavi():
    """Le chiavi RSA sono lente da generare: una sola volta per modulo."""
    garante = Garante()
    return garante, EmittentePrivato(garante)


@pytest.fixture
def rete(chiavi):
    garante, emittente = chiavi
    garante.buste_aperte = 0
    emittente.apri_conto("IT-TU", 100_00)
    emittente.apri_conto("IT-BAR", 0)
    pub, gpub = emittente.chiavi_pubbliche, garante.chiave_pubblica
    tu = PortafoglioPrivato("chip di Tu", pub, gpub)
    tu.preleva(emittente, "IT-TU", 20_00)
    return garante, emittente, tu, NegozioPrivato("Bar", pub, gpub), NegozioPrivato("Edicola", pub, gpub)


class TestComposizione:

    def test_prelievo_con_spiccioli(self):
        tagli = componi_prelievo(20_00)
        assert sum(tagli) == 20_00
        assert set(tagli) == set(TAGLI)

    def test_importo_non_componibile(self):
        with pytest.raises(ValueError):
            componi_prelievo(3)

    def test_scelta_esatta(self):
        monete = [Moneta(t, bytes([i]) * 32, 0) for i, t in enumerate([200, 100, 50, 20, 20, 5])]
        scelte = scegli_monete(monete, 1_45)
        assert sum(m.taglio for m in scelte) == 1_45
        assert scegli_monete(monete, 3) is None


class TestPrelievoCieco:

    def test_prelievo_scala_il_conto(self, rete):
        _, emittente, tu, _, _ = rete
        assert tu.saldo == 20_00
        assert emittente.conti["IT-TU"] == 80_00

    def test_monete_valide(self, rete):
        _, emittente, tu, _, _ = rete
        assert all(emittente.chiavi_pubbliche[m.taglio].verifica(m) for m in tu.monete)

    def test_emittente_non_collega_monete_al_prelievo(self, rete):
        _, emittente, tu, _, _ = rete
        assert not any(emittente.collega_al_prelievo(m) for m in tu.monete)

    def test_prelievo_senza_fondi(self, rete):
        _, emittente, tu, _, _ = rete
        emittente.apri_conto("IT-VUOTO", 0)
        with pytest.raises(ValueError):
            tu.preleva(emittente, "IT-VUOTO", 1_00)


class TestPagamentoPrivato:

    def test_pagamento_e_deposito(self, rete):
        garante, emittente, tu, bar, _ = rete
        spese = tu.paga("Bar", 1_50)
        assert bar.incassa(spese) == 1_50
        assert tu.saldo == 18_50
        esito = bar.deposita(emittente, "IT-BAR")
        assert esito.accreditato == 1_50
        assert emittente.conti["IT-BAR"] == 1_50
        assert bar.saldo == 0
        assert garante.buste_aperte == 0

    def test_moneta_falsa(self, rete):
        _, emittente, tu, bar, _ = rete
        vera = tu.paga("Bar", 2_00)[0]
        falsa = Spesa(Moneta(200, b"\x07" * 32, vera.moneta.firma), "Bar", vera.busta)
        with pytest.raises(ValueError, match="falsa"):
            bar.incassa([falsa])
        assert emittente.deposita("IT-BAR", [falsa]).rifiutate_false == 1

    def test_taglio_gonfiato(self, rete):
        _, _, tu, bar, _ = rete
        vera = tu.paga("Bar", 5)[0]
        gonfiata = Spesa(Moneta(200, vera.moneta.seriale, vera.moneta.firma), "Bar", vera.busta)
        with pytest.raises(ValueError, match="falsa"):
            bar.incassa([gonfiata])

    def test_stessa_moneta_due_volte_allo_stesso_pos(self, rete):
        _, _, tu, bar, _ = rete
        spese = tu.paga("Bar", 50)
        bar.incassa(spese)
        with pytest.raises(ValueError, match="già ricevuta"):
            bar.incassa(spese)
        assert bar.saldo == 50

    def test_destinatario_errato(self, rete):
        _, _, tu, _, edicola = rete
        with pytest.raises(ValueError, match="altro beneficiario"):
            edicola.incassa(tu.paga("Bar", 1_00))

    def test_monete_cancellate_dopo_la_spesa(self, rete):
        _, _, tu, _, _ = rete
        spese = tu.paga("Bar", 3_00)
        seriali = {s.moneta.seriale for s in spese}
        assert not seriali & {m.seriale for m in tu.monete}


class TestDoppiaSpesa:

    def test_clone_scoperto_dal_garante(self, rete):
        garante, emittente, tu, bar, edicola = rete
        emittente.apri_conto("IT-EDICOLA", 0)
        clone = copy.copy(tu)
        clone.monete = list(tu.monete)
        bar.incassa(tu.paga("Bar", 2_00))
        edicola.incassa(clone.paga("Edicola", 2_00))

        assert bar.deposita(emittente, "IT-BAR").accreditato == 2_00
        esito = edicola.deposita(emittente, "IT-EDICOLA")
        assert esito.accreditato == 0
        assert len(esito.doppie_spese) == 1

        prima, seconda = esito.doppie_spese[0]
        assert garante.apri(prima.busta) == ("chip di Tu", prima.moneta.seriale)
        assert garante.apri(seconda.busta) == ("chip di Tu", seconda.moneta.seriale)
        assert garante.buste_aperte == 2


def test_demo_privacy_completa():
    import demo_privacy
    assert demo_privacy.main() == 0
