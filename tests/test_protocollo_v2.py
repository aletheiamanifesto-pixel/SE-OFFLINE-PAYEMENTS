"""
test_protocollo_v2.py — Test del protocollo di pagamento offline v2

Copre: personalizzazione, blocco dei comandi v1, LOAD/UNLOAD firmati,
PAY/RECEIVE con tutti i controlli offline, recupero da NFC interrotto,
riconciliazione con scoperta della doppia spesa e lista revoche.
"""

import copy
import struct

import pytest

from bridge.emittente import Emittente, OperazioneRifiutata
from host_app.python import protocollo_v2 as v2
from host_app.python.pagamento_v2 import (
    ConnessioneInterrotta, ErroreProtocollo, TerminalePOS, consegna_pagamento,
    invia, richiedi_pagamento,
)
from host_app.python.se_simulator import SecureElementSimulator


def sw(risposta: bytes) -> int:
    return (risposta[-2] << 8) | risposta[-1]


def apdu(ins: int, data: bytes = b"") -> bytes:
    return bytes([0x80, ins, 0, 0, len(data)]) + data


@pytest.fixture
def rete():
    """Emittente + telefono carico con 50 € + POS del bar."""
    emittente = Emittente()
    emittente.apri_conto("IT-TU", 1_000_00)
    tu, chip_bar = SecureElementSimulator(), SecureElementSimulator()
    emittente.personalizza(tu, "Tu")
    emittente.personalizza(chip_bar, "Bar")
    emittente.carica("IT-TU", tu, 50_00)
    return emittente, tu, TerminalePOS(chip_bar, "Bar")


def clona(se: SecureElementSimulator) -> SecureElementSimulator:
    clone = SecureElementSimulator()
    clone.__dict__.update({k: copy.copy(v) for k, v in se.__dict__.items()})
    return clone


# =============================================================================
# PERSONALIZZAZIONE E BLOCCO DEL PROTOCOLLO v1
# =============================================================================

class TestPersonalizzazione:

    def test_personalizzazione_azzera_saldo_e_attiva_v2(self):
        se = SecureElementSimulator(initial_balance=10000)
        device_id = Emittente().personalizza(se, "Tu")
        assert se.personalizzato
        assert se.get_balance() == 0
        assert device_id == se.device_id

    def test_personalizzazione_una_sola_volta(self):
        se = SecureElementSimulator()
        Emittente().personalizza(se, "Tu")
        with pytest.raises(ErroreProtocollo):
            Emittente().personalizza(se, "Altro")

    def test_certificato_per_altra_chiave_rifiutato(self):
        emittente = Emittente()
        se, altro = SecureElementSimulator(), SecureElementSimulator()
        emittente.personalizza(altro, "Altro")
        risposta = se.process_apdu(bytes([0x00, 0xA4, 0, 0, 0]))
        risposta = se.process_apdu(apdu(v2.INS_PERSONALIZE,
                                        emittente.chiave_pubblica + altro._certificato))
        assert sw(risposta) == v2.SW_SECURITY_STATUS_NOT_SATISFIED
        assert not se.personalizzato

    def test_comandi_v1_bloccati_dopo_personalizzazione(self, rete):
        _, tu, _ = rete
        tu.process_apdu(bytes([0x00, 0xA4, 0, 0, 0]))
        importo = struct.pack(">I", 1_000_00)
        assert sw(tu.process_apdu(apdu(0x30, importo))) == v2.SW_SECURITY_STATUS_NOT_SATISFIED
        assert sw(tu.process_apdu(apdu(0x20, importo))) == v2.SW_SECURITY_STATUS_NOT_SATISFIED
        assert tu.credit(100) is False
        assert tu.debit(100) is False
        assert tu.get_balance() == 50_00

    def test_comandi_v1_funzionano_senza_personalizzazione(self):
        se = SecureElementSimulator(initial_balance=1000)
        assert se.credit(500) is True
        assert se.debit(200) is True
        assert se.get_balance() == 1300

    def test_sign_non_firma_messaggi_v2(self, rete):
        _, tu, _ = rete
        token_falso = v2.Token(tu.device_id, b"\x00" * 8, 1_000_00, 99).encode()
        tu.process_apdu(bytes([0x00, 0xA4, 0, 0, 0]))
        assert sw(tu.process_apdu(apdu(0x50, token_falso))) == v2.SW_SECURITY_STATUS_NOT_SATISFIED
        assert sw(tu.process_apdu(apdu(0x70, token_falso))) == v2.SW_SECURITY_STATUS_NOT_SATISFIED
        with pytest.raises(PermissionError):
            tu.sign_transaction(token_falso)
        assert sw(tu.process_apdu(apdu(0x50, b"ricevuta qualsiasi"))) == 0x9000


# =============================================================================
# CARICA E SCARICA (ONLINE)
# =============================================================================

class TestCaricaScarica:

    def test_carica_scala_il_conto(self, rete):
        emittente, tu, _ = rete
        assert tu.get_balance() == 50_00
        assert emittente.conti["IT-TU"] == 950_00
        assert emittente.in_circolazione() == 50_00

    def test_carica_oltre_limite_detenzione(self, rete):
        emittente, tu, _ = rete
        with pytest.raises(OperazioneRifiutata):
            emittente.carica("IT-TU", tu, 300_00)
        assert emittente.conti["IT-TU"] == 950_00

    def test_carica_conto_senza_fondi(self, rete):
        emittente, tu, _ = rete
        emittente.apri_conto("IT-VUOTO", 0)
        with pytest.raises(OperazioneRifiutata):
            emittente.carica("IT-VUOTO", tu, 1_00)

    def test_ordine_load_non_riutilizzabile(self, rete):
        emittente, tu, _ = rete
        ordine = emittente._ordine(v2.TAG_LOAD, tu.device_id, 10_00)
        invia(tu, v2.INS_LOAD, ordine)
        with pytest.raises(ErroreProtocollo) as e:
            invia(tu, v2.INS_LOAD, ordine)
        assert e.value.sw == v2.SW_REPLAY
        assert tu.get_balance() == 60_00

    def test_ordine_load_per_altro_chip(self, rete):
        emittente, tu, bar = rete
        ordine = emittente._ordine(v2.TAG_LOAD, bar.device_id, 10_00)
        with pytest.raises(ErroreProtocollo) as e:
            invia(tu, v2.INS_LOAD, ordine)
        assert e.value.sw == v2.SW_WRONG_DATA

    def test_ordine_load_firmato_da_falso_emittente(self, rete):
        _, tu, _ = rete
        ordine = Emittente()._ordine(v2.TAG_LOAD, tu.device_id, 10_00)
        with pytest.raises(ErroreProtocollo) as e:
            invia(tu, v2.INS_LOAD, ordine)
        assert e.value.sw == v2.SW_SECURITY_STATUS_NOT_SATISFIED

    def test_scarica_accredita_il_conto(self, rete):
        emittente, tu, _ = rete
        emittente.scarica(tu, "IT-TU", 20_00)
        assert tu.get_balance() == 30_00
        assert emittente.conti["IT-TU"] == 970_00
        assert emittente.in_circolazione() == 30_00

    def test_scarica_saldo_insufficiente(self, rete):
        emittente, tu, _ = rete
        with pytest.raises(OperazioneRifiutata):
            emittente.scarica(tu, "IT-TU", 60_00)


# =============================================================================
# PAGAMENTO OFFLINE
# =============================================================================

class TestPagamentoOffline:

    def test_pagamento_riuscito(self, rete):
        _, tu, bar = rete
        pacchetto = bar.incassa(tu, 1_50)
        assert tu.get_balance() == 48_50
        assert bar.chip.get_balance() == 1_50
        assert pacchetto.token.contatore == 1
        assert pacchetto.token.payee_id == bar.device_id
        assert len(pacchetto.encode()) == v2.PACCHETTO_LEN <= 255

    def test_replay_bloccato(self, rete):
        _, tu, bar = rete
        pacchetto = bar.incassa(tu, 1_50)
        with pytest.raises(ErroreProtocollo) as e:
            bar.ricevi(pacchetto)
        assert e.value.sw == v2.SW_REPLAY
        assert bar.chip.get_balance() == 1_50

    def test_token_manomesso(self, rete):
        _, tu, bar = rete
        p = richiedi_pagamento(tu, bar.device_id, 1_50)
        t = p.token
        falso = v2.Pacchetto(v2.Token(t.payer_id, t.payee_id, 40_00, t.contatore), p.firma, p.certificato)
        with pytest.raises(ErroreProtocollo) as e:
            bar.ricevi(falso)
        assert e.value.sw == v2.SW_SECURITY_STATUS_NOT_SATISFIED

    def test_destinatario_errato(self, rete):
        emittente, tu, bar = rete
        edicola = SecureElementSimulator()
        emittente.personalizza(edicola, "Edicola")
        p = richiedi_pagamento(tu, bar.device_id, 1_50)
        with pytest.raises(ErroreProtocollo) as e:
            consegna_pagamento(edicola, p)
        assert e.value.sw == v2.SW_WRONG_DATA

    def test_chip_di_falso_emittente(self, rete):
        _, _, bar = rete
        falsario = Emittente()
        falso = SecureElementSimulator()
        falsario.personalizza(falso, "Falsario")
        falsario.apri_conto("X", 100_00)
        falsario.carica("X", falso, 50_00)
        with pytest.raises(ErroreProtocollo) as e:
            bar.incassa(falso, 10_00)
        assert e.value.sw == v2.SW_SECURITY_STATUS_NOT_SATISFIED
        assert bar.chip.get_balance() == 0

    def test_saldo_insufficiente(self, rete):
        _, tu, bar = rete
        with pytest.raises(ErroreProtocollo) as e:
            bar.incassa(tu, 51_00)
        assert e.value.sw == 0x6985
        assert tu.get_balance() == 50_00
        assert tu.get_counter() == 0

    def test_pagare_se_stessi_rifiutato(self, rete):
        _, tu, _ = rete
        with pytest.raises(ErroreProtocollo):
            richiedi_pagamento(tu, tu.device_id, 1_00)

    def test_limite_detenzione_del_beneficiario(self):
        emittente = Emittente()
        emittente.apri_conto("A", 1_000_00)
        tu, bar = SecureElementSimulator(), SecureElementSimulator()
        emittente.personalizza(tu, "Tu")
        emittente.personalizza(bar, "Bar", limite=10_00)
        emittente.carica("A", tu, 50_00)
        with pytest.raises(ErroreProtocollo) as e:
            TerminalePOS(bar).incassa(tu, 20_00)
        assert e.value.sw == v2.SW_LIMIT_EXCEEDED

    def test_recupero_dopo_nfc_interrotto(self, rete):
        _, tu, bar = rete
        with pytest.raises(ConnessioneInterrotta):
            bar.incassa(tu, 3_00, interrompi_dopo_pay=True)
        assert tu.get_balance() == 47_00
        assert bar.chip.get_balance() == 0
        bar.riprendi_pagamento_interrotto(tu)
        assert bar.chip.get_balance() == 3_00
        with pytest.raises(ErroreProtocollo):
            bar.riprendi_pagamento_interrotto(tu)
        assert bar.chip.get_balance() == 3_00


# =============================================================================
# RICONCILIAZIONE E REVOCHE
# =============================================================================

class TestRiconciliazione:

    def test_sincronizzazione_normale(self, rete):
        emittente, tu, bar = rete
        bar.incassa(tu, 1_00)
        bar.incassa(tu, 2_00)
        r = emittente.sincronizza(bar.svuota_registro())
        assert (r.accettati, r.duplicati, r.non_validi, r.doppie_spese) == (2, 0, 0, [])
        assert emittente.revocati == set()

    def test_stesso_pacchetto_due_volte_non_e_frode(self, rete):
        emittente, tu, bar = rete
        p = bar.incassa(tu, 1_00)
        emittente.sincronizza([p])
        r = emittente.sincronizza([p])
        assert r.duplicati == 1 and r.doppie_spese == []

    def test_pacchetto_non_valido(self, rete):
        emittente, tu, bar = rete
        p = bar.incassa(tu, 1_00)
        falso = v2.Pacchetto(v2.Token(p.token.payer_id, p.token.payee_id, 9_00, 7), p.firma, p.certificato)
        assert emittente.sincronizza([falso]).non_validi == 1

    def test_doppia_spesa_scoperta_e_revocata(self, rete):
        emittente, tu, bar = rete
        edicola = TerminalePOS(SecureElementSimulator(), "Edicola")
        emittente.personalizza(edicola.chip, "Edicola")
        clone = clona(tu)
        bar.incassa(tu, 20_00)
        edicola.incassa(clone, 20_00)

        emittente.sincronizza(bar.svuota_registro())
        r = emittente.sincronizza(edicola.svuota_registro())
        assert len(r.doppie_spese) == 1
        assert r.doppie_spese[0].payer_id == tu.device_id
        assert tu.device_id in emittente.revocati
        assert emittente.perdite == 20_00

        assert emittente.distribuisci_revoche(bar.chip) is True
        assert emittente.distribuisci_revoche(bar.chip) is False
        with pytest.raises(ErroreProtocollo) as e:
            bar.incassa(clone, 1_00)
        assert e.value.sw == v2.SW_REVOKED
        with pytest.raises(OperazioneRifiutata):
            emittente.carica("IT-TU", tu, 1_00)

    def test_pagamento_da_revocato_contato_come_perdita(self, rete):
        emittente, tu, bar = rete
        emittente.revoca(tu.device_id)
        r = emittente.sincronizza([bar.incassa(tu, 5_00)])  # il bar non ha ancora le revoche
        assert r.da_revocati == 1
        assert emittente.perdite == 5_00

    def test_lista_revoche_falsa_o_vecchia(self, rete):
        emittente, _, bar = rete
        emittente.revoca(b"\x01" * 8)
        lista_v1 = emittente.lista_revoche()
        invia(bar.chip, v2.INS_UPDATE_REVOCATIONS, lista_v1)
        with pytest.raises(ErroreProtocollo) as e:
            invia(bar.chip, v2.INS_UPDATE_REVOCATIONS, lista_v1)
        assert e.value.sw == v2.SW_REPLAY

        falsario = Emittente()
        falsario.versione_revoche = 99
        with pytest.raises(ErroreProtocollo) as e:
            invia(bar.chip, v2.INS_UPDATE_REVOCATIONS, falsario.lista_revoche())
        assert e.value.sw == v2.SW_SECURITY_STATUS_NOT_SATISFIED


def test_demo_completa():
    """La demo deve terminare con tutti i controlli attesi (exit code 0)."""
    import demo
    assert demo.main() == 0
