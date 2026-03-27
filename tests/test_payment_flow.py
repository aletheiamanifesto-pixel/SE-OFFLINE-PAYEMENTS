"""
test_payment_flow.py — Test automatici per il sistema di pagamento offline AEGIS

Questi test verificano ogni componente del sistema, dal singolo comando APDU
fino al flusso completo di pagamento. È come un collaudo in fabbrica:
ogni pezzo viene testato singolarmente, poi si testa la macchina intera.

Esecuzione: pytest tests/test_payment_flow.py -v
"""

import struct
import sys
import os
import time

import pytest

# Aggiungiamo il percorso del progetto per permettere gli import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from host_app.python.se_simulator import (
    SecureElementSimulator, SW_OK, SW_INSUFFICIENT_BALANCE, SW_WRONG_LENGTH,
    SW_INS_NOT_SUPPORTED
)
from bridge.reconciliation_bridge import ReconciliationBridge


def _estrai_sw(risposta: bytes) -> int:
    """Estrae la status word dagli ultimi 2 byte della risposta APDU."""
    return (risposta[-2] << 8) | risposta[-1]


# =============================================================================
# TEST 1: Selezione dell'applet
# Come verificare che la carta venga riconosciuta dal lettore
# =============================================================================

class TestSelectApplet:
    """Test per il comando SELECT — l'applet deve attivarsi correttamente."""

    def test_select_applet(self):
        """
        Verifica che il comando SELECT (CLA=0x00, INS=0xA4) funzioni.
        È come inserire la carta nel POS: deve rispondere "pronta".
        """
        se = SecureElementSimulator()

        # Costruiamo il comando SELECT standard ISO 7816
        apdu_select = SecureElementSimulator.build_apdu(0x00, 0xA4)
        risposta = se.process_apdu(apdu_select)

        # La risposta deve essere solo la status word 0x9000 (OK)
        assert _estrai_sw(risposta) == SW_OK, \
            "Il comando SELECT deve restituire SW_OK (0x9000)"


# =============================================================================
# TEST 2: Lettura del saldo
# Come controllare quanto hai sulla carta al bancomat
# =============================================================================

class TestGetBalance:
    """Test per il comando GET_BALANCE — il saldo deve essere corretto."""

    def test_get_balance(self):
        """
        Verifica che GET_BALANCE restituisca il saldo iniziale corretto.
        Con 10000 centesimi (100.00€), i 4 byte devono codificare 10000.
        """
        se = SecureElementSimulator(initial_balance=10000)

        apdu_balance = SecureElementSimulator.build_apdu(0x80, 0x10)
        risposta = se.process_apdu(apdu_balance)

        assert _estrai_sw(risposta) == SW_OK
        # I primi 4 byte sono il saldo in big-endian
        saldo = struct.unpack('>I', risposta[:-2])[0]
        assert saldo == 10000, f"Saldo atteso: 10000, ottenuto: {saldo}"

    def test_get_balance_custom(self):
        """
        Verifica che un saldo personalizzato venga restituito correttamente.
        Come verificare che la carta prepagata sia stata caricata con l'importo giusto.
        """
        se = SecureElementSimulator(initial_balance=5000)
        assert se.get_balance() == 5000


# =============================================================================
# TEST 3: Addebito (DEBIT)
# Come prelevare contanti al bancomat
# =============================================================================

class TestDebit:
    """Test per il comando DEBIT — deve scalare il saldo correttamente."""

    def test_debit_success(self):
        """
        Verifica che un addebito valido riduca il saldo correttamente.
        Se hai 100€ e prelevi 25€, devi averne 75€.
        """
        se = SecureElementSimulator(initial_balance=10000)

        # Addebitiamo 2500 centesimi (25.00€)
        importo = struct.pack('>I', 2500)
        apdu_debit = SecureElementSimulator.build_apdu(0x80, 0x20, data=importo)
        risposta = se.process_apdu(apdu_debit)

        assert _estrai_sw(risposta) == SW_OK
        nuovo_saldo = struct.unpack('>I', risposta[:-2])[0]
        assert nuovo_saldo == 7500, \
            f"Dopo addebito di 25€ da 100€, atteso 75€ (7500 cent), ottenuto: {nuovo_saldo}"

    def test_debit_insufficient_balance(self):
        """
        Verifica che l'addebito fallisca se il saldo è insufficiente.
        Come quando il bancomat dice "fondi non disponibili".
        """
        se = SecureElementSimulator(initial_balance=1000)  # Solo 10.00€

        # Proviamo ad addebitare 5000 centesimi (50.00€) — impossibile!
        importo = struct.pack('>I', 5000)
        apdu_debit = SecureElementSimulator.build_apdu(0x80, 0x20, data=importo)
        risposta = se.process_apdu(apdu_debit)

        assert _estrai_sw(risposta) == SW_INSUFFICIENT_BALANCE, \
            "Addebito superiore al saldo deve restituire SW_INSUFFICIENT_BALANCE"

    def test_debit_wrong_length(self):
        """
        Verifica che un DEBIT con dati troppo corti fallisca.
        Come compilare un modulo di prelievo senza scrivere l'importo.
        """
        se = SecureElementSimulator()

        # Mandiamo solo 2 byte invece di 4
        apdu_debit = SecureElementSimulator.build_apdu(0x80, 0x20, data=b'\x00\x01')
        risposta = se.process_apdu(apdu_debit)

        assert _estrai_sw(risposta) == SW_WRONG_LENGTH

    def test_debit_via_method(self):
        """
        Verifica il metodo debit() ad alto livello.
        Come usare l'app della banca invece del bancomat.
        """
        se = SecureElementSimulator(initial_balance=10000)

        assert se.debit(3000) is True, "Addebito di 30€ da 100€ deve riuscire"
        assert se.get_balance() == 7000, "Saldo dopo addebito deve essere 70€"

        assert se.debit(50000) is False, "Addebito di 500€ da 70€ deve fallire"
        assert se.get_balance() == 7000, "Saldo non deve cambiare dopo addebito fallito"


# =============================================================================
# TEST 4: Accredito (CREDIT)
# Come versare contanti al bancomat
# =============================================================================

class TestCredit:
    """Test per il comando CREDIT — deve aumentare il saldo correttamente."""

    def test_credit(self):
        """
        Verifica che un accredito aumenti il saldo.
        Se hai 50€ e versi 25€, devi averne 75€.
        """
        se = SecureElementSimulator(initial_balance=5000)

        importo = struct.pack('>I', 2500)
        apdu_credit = SecureElementSimulator.build_apdu(0x80, 0x30, data=importo)
        risposta = se.process_apdu(apdu_credit)

        assert _estrai_sw(risposta) == SW_OK
        nuovo_saldo = struct.unpack('>I', risposta[:-2])[0]
        assert nuovo_saldo == 7500

    def test_credit_via_method(self):
        """
        Verifica il metodo credit() ad alto livello.
        Come ricevere un bonifico sull'app.
        """
        se = SecureElementSimulator(initial_balance=5000)

        assert se.credit(3000) is True
        assert se.get_balance() == 8000


# =============================================================================
# TEST 5: Contatore monotònico
# Come il contachilometri: sale a ogni transazione e non torna indietro
# =============================================================================

class TestCounter:
    """Test per il contatore monotònico — deve incrementare solo su DEBIT."""

    def test_counter_increments(self):
        """
        Verifica che il contatore si incrementi a ogni addebito.
        Come il numero di scontrino: ogni vendita ne stacca uno nuovo.
        """
        se = SecureElementSimulator(initial_balance=10000)

        # All'inizio il contatore è 0
        assert se.get_counter() == 0, "Il contatore iniziale deve essere 0"

        # Dopo un addebito, il contatore deve essere 1
        se.debit(1000)
        assert se.get_counter() == 1, "Dopo 1 addebito, il contatore deve essere 1"

        # Dopo un altro addebito, il contatore deve essere 2
        se.debit(1000)
        assert se.get_counter() == 2, "Dopo 2 addebiti, il contatore deve essere 2"

    def test_counter_no_increment_on_credit(self):
        """
        Verifica che il contatore NON si incrementi su accredito.
        Come il contachilometri che non sale quando fai retromarcia
        (gli accrediti non sono "movimenti in uscita").
        """
        se = SecureElementSimulator(initial_balance=5000)

        se.credit(1000)
        assert se.get_counter() == 0, \
            "Il contatore non deve incrementare su accredito"

    def test_counter_via_apdu(self):
        """Verifica il contatore tramite comando APDU GET_COUNTER."""
        se = SecureElementSimulator(initial_balance=10000)
        se.debit(500)

        apdu_counter = SecureElementSimulator.build_apdu(0x80, 0x40)
        risposta = se.process_apdu(apdu_counter)

        assert _estrai_sw(risposta) == SW_OK
        contatore = struct.unpack('>I', risposta[:-2])[0]
        assert contatore == 1


# =============================================================================
# TEST 6: Firma digitale ECDSA
# Come verificare che la firma autografa su un assegno sia autentica
# =============================================================================

class TestSignAndVerify:
    """Test per la firma ECDSA — firma e verifica devono funzionare correttamente."""

    def test_sign_and_verify(self):
        """
        Verifica il ciclo completo: firma → verifica.
        Come firmare un assegno e poi farlo controllare dalla banca.
        """
        se = SecureElementSimulator()

        # Dati da firmare (simulano i dati di una transazione)
        dati = b"Pagamento di 25.00 EUR da Alice a Bob"

        # Il SE firma i dati
        firma = se.sign_transaction(dati)
        assert len(firma) > 0, "La firma non deve essere vuota"

        # Otteniamo la chiave pubblica per la verifica
        chiave_pubblica = se.get_certificate()
        assert len(chiave_pubblica) == 65, \
            "La chiave pubblica uncompressed deve essere 65 byte"

        # Verifichiamo la firma — deve essere valida
        assert se.verify_signature(dati, firma, chiave_pubblica) is True, \
            "La firma deve essere verificata positivamente"

    def test_sign_verify_wrong_data(self):
        """
        Verifica che una firma NON sia valida per dati diversi.
        Come quando la banca scopre che l'assegno è stato alterato.
        """
        se = SecureElementSimulator()

        dati_originali = b"Importo: 25.00 EUR"
        dati_alterati = b"Importo: 250.00 EUR"

        firma = se.sign_transaction(dati_originali)
        chiave_pubblica = se.get_certificate()

        # La firma dei dati originali NON deve validare i dati alterati
        assert se.verify_signature(dati_alterati, firma, chiave_pubblica) is False, \
            "Una firma non deve essere valida per dati diversi da quelli firmati"

    def test_sign_via_apdu(self):
        """
        Verifica la firma tramite comando APDU SIGN.
        Come usare il POS per firmare una transazione.
        """
        se = SecureElementSimulator()

        dati = b"test transaction data"
        apdu_sign = SecureElementSimulator.build_apdu(0x80, 0x50, data=dati)
        risposta = se.process_apdu(apdu_sign)

        assert _estrai_sw(risposta) == SW_OK
        firma = risposta[:-2]
        assert len(firma) > 0

    def test_different_keys_fail_verification(self):
        """
        Verifica che la firma di un SE non sia valida con la chiave di un altro.
        Come quando qualcuno prova a usare la firma di un'altra persona.
        """
        se_alice = SecureElementSimulator()
        se_bob = SecureElementSimulator()

        dati = b"Transazione di Alice"
        firma_alice = se_alice.sign_transaction(dati)
        chiave_bob = se_bob.get_certificate()

        # La firma di Alice NON deve essere valida con la chiave di Bob
        assert se_alice.verify_signature(dati, firma_alice, chiave_bob) is False, \
            "La firma di Alice non deve essere verificabile con la chiave di Bob"


# =============================================================================
# TEST 7: Flusso di pagamento completo end-to-end
# Come testare l'intero processo di acquisto al mercato
# =============================================================================

class TestFullPaymentFlow:
    """Test end-to-end del flusso di pagamento completo."""

    def test_full_payment_flow(self):
        """
        Simula un pagamento completo: Alice paga 25€ a Bob.
        Verifica che tutti i saldi, contatori e firme siano corretti.
        """
        # Prepariamo i due portafogli
        alice = SecureElementSimulator(initial_balance=10000)  # 100€
        bob = SecureElementSimulator(initial_balance=5000)      # 50€

        importo = 2500  # 25.00€

        # PASSO 1: SELECT su entrambi
        apdu_select = SecureElementSimulator.build_apdu(0x00, 0xA4)
        assert _estrai_sw(alice.process_apdu(apdu_select)) == SW_OK
        assert _estrai_sw(bob.process_apdu(apdu_select)) == SW_OK

        # PASSO 2: Verifica saldi iniziali
        assert alice.get_balance() == 10000
        assert bob.get_balance() == 5000

        # PASSO 3: Alice paga (DEBIT)
        assert alice.debit(importo) is True
        assert alice.get_balance() == 7500  # 100€ - 25€ = 75€

        # PASSO 4: Bob incassa (CREDIT)
        assert bob.credit(importo) is True
        assert bob.get_balance() == 7500  # 50€ + 25€ = 75€

        # PASSO 5: Alice firma la transazione
        # Formato: importo (4 byte) + contatore (4 byte) + timestamp (8 byte) = 16 byte
        dati_tx = struct.pack('>IIQ', importo, alice.get_counter(), int(time.time()))
        firma = alice.sign_transaction(dati_tx)
        assert len(firma) > 0

        # PASSO 6: Bob verifica la firma di Alice
        chiave_alice = alice.get_certificate()
        assert bob.verify_signature(dati_tx, firma, chiave_alice) is True

        # PASSO 7: Verifica contatori
        # Alice ha fatto un debit → contatore = 1
        # Bob non ha fatto debit → contatore = 0
        assert alice.get_counter() == 1
        assert bob.get_counter() == 0

    def test_unsupported_instruction(self):
        """
        Verifica che un comando APDU sconosciuto restituisca l'errore corretto.
        Come chiedere un servizio inesistente allo sportello.
        """
        se = SecureElementSimulator()

        # INS=0xFF non esiste
        apdu_sconosciuto = SecureElementSimulator.build_apdu(0x80, 0xFF)
        risposta = se.process_apdu(apdu_sconosciuto)

        assert _estrai_sw(risposta) == SW_INS_NOT_SUPPORTED


# =============================================================================
# TEST 8: Ponte di riconciliazione
# Come verificare che il commercialista registri correttamente gli scontrini
# =============================================================================

class TestReconciliationBridge:
    """Test per il ReconciliationBridge — la riconciliazione offline → blockchain."""

    def test_reconciliation_bridge(self):
        """
        Verifica il flusso completo del bridge:
        aggiunta transazione → verifica → riconciliazione.
        """
        bridge = ReconciliationBridge()

        # Aggiungiamo una transazione valida
        tx = {
            "sender_id": "alice_se_001",
            "receiver_id": "bob_se_002",
            "amount": 2500,
            "counter": 1,
            "signature": "abcdef1234567890",
            "timestamp": time.time()
        }

        assert bridge.add_transaction(tx) is True, \
            "L'aggiunta di una transazione valida deve riuscire"

        # Verifichiamo che sia nella coda pendente
        pendenti = bridge.get_pending_transactions()
        assert len(pendenti) == 1, "Deve esserci 1 transazione pendente"
        assert pendenti[0]["amount"] == 2500

        # Verifichiamo la transazione
        assert bridge.verify_transaction(tx) is True, \
            "La transazione valida deve superare la verifica"

        # Riconciliamo
        risultato = bridge.reconcile()
        assert risultato["successi"] == 1, "La riconciliazione deve avere 1 successo"
        assert risultato["fallimenti"] == 0, "Non ci devono essere fallimenti"

        # Dopo la riconciliazione, la coda pendente deve essere vuota
        assert len(bridge.get_pending_transactions()) == 0, \
            "Dopo la riconciliazione, non devono esserci transazioni pendenti"

    def test_add_invalid_transaction(self):
        """
        Verifica che una transazione con campi mancanti venga rifiutata.
        Come imbucare una lettera senza indirizzo: viene respinta.
        """
        bridge = ReconciliationBridge()

        # Transazione senza il campo 'signature'
        tx_incompleta = {
            "sender_id": "alice",
            "receiver_id": "bob",
            "amount": 1000,
            "counter": 0
        }

        assert bridge.add_transaction(tx_incompleta) is False

    def test_verify_invalid_amount(self):
        """
        Verifica che una transazione con importo non valido fallisca.
        Come provare a fare un bonifico di 0€.
        """
        bridge = ReconciliationBridge()

        tx = {
            "sender_id": "alice",
            "receiver_id": "bob",
            "amount": 0,
            "counter": 1,
            "signature": "abc123"
        }

        assert bridge.verify_transaction(tx) is False
