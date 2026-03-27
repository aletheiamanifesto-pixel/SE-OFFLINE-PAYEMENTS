"""
test_hardware_integration.py — Test per l'integrazione con hardware reale

Questo modulo contiene test per verificare il funzionamento del codice
con hardware reale (lettori ACR122U, smart card JCOP4) e con i nuovi
componenti architetturali (interfaccia, factory, profili).

I test marcati con @pytest.mark.hardware vengono saltati automaticamente
se non c'è un lettore NFC collegato — permettono di eseguire l'intera
suite di test senza hardware, ricevendo semplicemente uno skip invece
di un fallimento.

ESECUZIONE:
  # Solo test senza hardware (tutti gli altri test)
  pytest tests/ -v

  # Includi i test hardware (richiede lettore ACR122U + smart card)
  pytest tests/ -v -m hardware

  # Solo i test dell'interfaccia e della factory (nessun hardware)
  pytest tests/test_hardware_integration.py -v -m "not hardware"
"""

import os
import sys
import struct

import pytest

# Aggiungiamo il percorso del progetto per permettere gli import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from host_app.python.se_simulator import SecureElementSimulator
from host_app.python.se_interface import SecureElementInterface
from host_app.python.hardware_errors import (
    HardwareError, CardNotFoundError, NFCTimeoutError,
    CardCommunicationError, TornTransactionError, AppletNotFoundError
)
from host_app.python.se_factory import create_secure_element, create_from_profile
from host_app.python.resilient_payment import ResilientPaymentFlow


# =============================================================================
# FIXTURE — Configurazione comune ai test
# =============================================================================

@pytest.fixture
def simulatore():
    """Crea un simulatore con saldo iniziale standard per i test."""
    return SecureElementSimulator(initial_balance=10000)


@pytest.fixture
def simulatore_vuoto():
    """Crea un simulatore con saldo zero per testare casi limite."""
    return SecureElementSimulator(initial_balance=0)


@pytest.fixture
def coppia_simulatori():
    """Crea una coppia di simulatori per test di pagamento."""
    pagatore = SecureElementSimulator(initial_balance=10000)
    ricevente = SecureElementSimulator(initial_balance=5000)
    return pagatore, ricevente


@pytest.fixture
def lettore_acr122u():
    """
    Fixture per il lettore ACR122U — salta il test se non disponibile.

    Verifica la presenza di pyscard e di un lettore fisico collegato.
    Se manca uno dei due, salta il test con un messaggio esplicativo.
    """
    try:
        from smartcard.System import readers
        available = readers()
        if not available:
            pytest.skip("Nessun lettore PC/SC disponibile — collega l'ACR122U")
        return available[0]
    except ImportError:
        pytest.skip("pyscard non installato — esegui: pip install pyscard")


# =============================================================================
# TEST 1: Interfaccia astratta SecureElementInterface
# Verifica che l'interfaccia sia implementata correttamente
# =============================================================================

class TestSecureElementInterface:
    """
    Verifica che SecureElementInterface funzioni come contratto astratto.

    Questi test non richiedono hardware — lavorano solo con il simulatore
    e verificano che l'architettura sia corretta.
    """

    def test_simulatore_implementa_interfaccia(self, simulatore):
        """
        Il simulatore deve essere un'istanza di SecureElementInterface.
        Verifica che l'ereditarietà sia stata aggiunta correttamente.
        """
        assert isinstance(simulatore, SecureElementInterface), \
            "SecureElementSimulator deve ereditare da SecureElementInterface"

    def test_interfaccia_non_istanziabile(self):
        """
        Non si può creare un'istanza diretta dell'interfaccia astratta.
        Questo garantisce che nessuno usi l'interfaccia "nuda" per errore.
        """
        with pytest.raises(TypeError):
            SecureElementInterface()

    def test_tutti_metodi_presenti(self, simulatore):
        """
        Verifica che tutti i metodi obbligatori dell'interfaccia siano presenti.
        """
        metodi_richiesti = [
            "process_apdu", "get_balance", "debit", "credit",
            "get_counter", "sign_transaction", "verify_signature", "get_certificate"
        ]
        for metodo in metodi_richiesti:
            assert hasattr(simulatore, metodo), \
                f"Metodo '{metodo}' mancante in SecureElementSimulator"
            assert callable(getattr(simulatore, metodo)), \
                f"'{metodo}' non è callable"

    def test_interfaccia_accetta_simulatore_come_parametro(self, simulatore):
        """
        Una funzione che accetta SecureElementInterface deve accettare il simulatore.
        Verifica il duck typing / polimorfismo.
        """
        def usa_se(se: SecureElementInterface) -> int:
            return se.get_balance()

        saldo = usa_se(simulatore)
        assert saldo == 10000


# =============================================================================
# TEST 2: Eccezioni hardware personalizzate
# =============================================================================

class TestHardwareErrors:
    """Verifica che le eccezioni hardware siano definite correttamente."""

    def test_gerarchia_eccezioni(self):
        """
        Tutte le eccezioni specifiche devono ereditare da HardwareError.
        Questo permette di catturarle tutte con un unico except.
        """
        assert issubclass(CardNotFoundError, HardwareError)
        assert issubclass(NFCTimeoutError, HardwareError)
        assert issubclass(CardCommunicationError, HardwareError)
        assert issubclass(TornTransactionError, HardwareError)
        assert issubclass(AppletNotFoundError, HardwareError)

    def test_torn_transaction_attributi(self):
        """
        TornTransactionError deve contenere informazioni sulla transazione parziale.
        """
        errore = TornTransactionError(
            "Transazione interrotta",
            amount=2500,
            payer_debited=True,
            receiver_credited=False
        )
        assert errore.amount == 2500
        assert errore.payer_debited is True
        assert errore.receiver_credited is False
        assert "Transazione interrotta" in str(errore)

    def test_applet_not_found_attributi(self):
        """
        AppletNotFoundError deve contenere l'AID dell'applet non trovato.
        """
        aid = bytes.fromhex("D2760000604101")
        errore = AppletNotFoundError("Applet non trovato", aid=aid)
        assert errore.aid == aid
        assert errore.aid_hex == "D2760000604101"

    def test_eccezioni_sono_istanze_di_exception(self):
        """Tutte le eccezioni devono essere compatibili con il sistema di exception standard."""
        for cls in [HardwareError, CardNotFoundError, NFCTimeoutError,
                    CardCommunicationError, TornTransactionError, AppletNotFoundError]:
            assert issubclass(cls, Exception), f"{cls.__name__} deve ereditare da Exception"


# =============================================================================
# TEST 3: Factory create_secure_element
# =============================================================================

class TestSeFactory:
    """Test per la factory che crea il backend corretto."""

    def test_factory_crea_simulatore(self):
        """La factory deve creare un simulatore quando backend='simulator'."""
        se = create_secure_element("simulator", initial_balance=5000)
        assert isinstance(se, SecureElementInterface)
        assert isinstance(se, SecureElementSimulator)
        assert se.get_balance() == 5000

    def test_factory_simulatore_saldo_default(self):
        """Il simulatore creato dalla factory deve avere saldo di default."""
        se = create_secure_element("simulator")
        assert se.get_balance() == 10000  # Default: 100€

    def test_factory_backend_sconosciuto(self):
        """La factory deve sollevare ValueError per backend non riconosciuti."""
        with pytest.raises(ValueError) as exc_info:
            create_secure_element("backend_inesistente")
        assert "backend_inesistente" in str(exc_info.value)
        assert "simulator" in str(exc_info.value)

    def test_factory_crea_da_profilo_development(self):
        """La factory deve creare correttamente dall'oggetto profilo 'development'."""
        profilo = {
            "backend": "simulator",
            "initial_balance": 7500
        }
        se = create_from_profile(profilo)
        assert isinstance(se, SecureElementInterface)
        assert se.get_balance() == 7500

    def test_factory_profilo_senza_backend_solleva_errore(self):
        """Un profilo senza il campo 'backend' deve sollevare KeyError."""
        profilo_invalido = {"initial_balance": 5000}  # manca 'backend'
        with pytest.raises(KeyError):
            create_from_profile(profilo_invalido)

    def test_factory_pcscard_senza_hardware(self):
        """
        La factory per pcscard deve sollevare ImportError o CardNotFoundError
        se pyscard non è installato o non c'è hardware.
        """
        try:
            create_secure_element("pcscard")
            pytest.skip("Hardware disponibile — test non applicabile")
        except (ImportError, CardNotFoundError):
            pass  # Comportamento atteso senza hardware


# =============================================================================
# TEST 4: Profili hardware YAML
# =============================================================================

class TestHardwareProfiles:
    """Test per il caricamento e l'utilizzo dei profili hardware."""

    def test_file_profili_esiste(self):
        """Il file config/hardware_profiles.yaml deve esistere."""
        profilo_path = os.path.join(
            os.path.dirname(__file__), '..', 'config', 'hardware_profiles.yaml'
        )
        assert os.path.exists(profilo_path), \
            "Il file config/hardware_profiles.yaml non esiste"

    def test_profili_caricabili(self):
        """Il file YAML deve essere leggibile e contenere i profili attesi."""
        try:
            import yaml
        except ImportError:
            pytest.skip("pyyaml non installato — esegui: pip install pyyaml")

        profilo_path = os.path.join(
            os.path.dirname(__file__), '..', 'config', 'hardware_profiles.yaml'
        )
        with open(profilo_path) as f:
            config = yaml.safe_load(f)

        assert "profiles" in config, "Il file YAML deve contenere la chiave 'profiles'"
        profili = config["profiles"]

        # Verifica i profili obbligatori
        assert "development" in profili, "Profilo 'development' mancante"
        assert "test_acr122u" in profili, "Profilo 'test_acr122u' mancante"
        assert "test_android" in profili, "Profilo 'test_android' mancante"

    def test_profilo_development_valido(self):
        """Il profilo 'development' deve creare un simulatore funzionante."""
        try:
            import yaml
        except ImportError:
            pytest.skip("pyyaml non installato")

        profilo_path = os.path.join(
            os.path.dirname(__file__), '..', 'config', 'hardware_profiles.yaml'
        )
        with open(profilo_path) as f:
            config = yaml.safe_load(f)

        profilo = config["profiles"]["development"]
        se = create_from_profile(profilo)
        assert isinstance(se, SecureElementInterface)
        assert se.get_balance() > 0

    def test_profilo_acr122u_ha_campi_richiesti(self):
        """Il profilo ACR122U deve contenere tutti i campi necessari."""
        try:
            import yaml
        except ImportError:
            pytest.skip("pyyaml non installato")

        profilo_path = os.path.join(
            os.path.dirname(__file__), '..', 'config', 'hardware_profiles.yaml'
        )
        with open(profilo_path) as f:
            config = yaml.safe_load(f)

        profilo = config["profiles"]["test_acr122u"]
        assert "backend" in profilo
        assert "aid" in profilo
        assert "timeout_ms" in profilo
        assert "retries" in profilo
        assert profilo["backend"] == "pcscard"


# =============================================================================
# TEST 5: ResilientPaymentFlow con simulatore
# =============================================================================

class TestResilientPaymentFlow:
    """
    Test per il flusso di pagamento resiliente.

    Questi test usano il simulatore ma verificano la logica di retry e rollback
    che sarà usata anche con hardware reale.
    """

    def test_pagamento_semplice_riuscito(self, coppia_simulatori):
        """Un pagamento semplice tra due simulatori deve riuscire."""
        pagatore, ricevente = coppia_simulatori
        flusso = ResilientPaymentFlow(max_retries=3)

        successo = flusso.esegui_pagamento(pagatore, ricevente, importo=2500)

        assert successo is True
        assert pagatore.get_balance() == 7500   # 100€ - 25€ = 75€
        assert ricevente.get_balance() == 7500  # 50€ + 25€ = 75€

    def test_pagamento_saldo_insufficiente(self, coppia_simulatori):
        """Il pagamento deve fallire se il saldo è insufficiente."""
        pagatore, ricevente = coppia_simulatori
        flusso = ResilientPaymentFlow()

        # Prova a pagare 200€ quando il pagatore ha solo 100€
        successo = flusso.esegui_pagamento(pagatore, ricevente, importo=20000)

        assert successo is False
        # I saldi devono rimanere invariati
        assert pagatore.get_balance() == 10000
        assert ricevente.get_balance() == 5000

    def test_pagamento_importo_negativo_solleva_errore(self, coppia_simulatori):
        """Un importo negativo deve sollevare ValueError, non fallire silenziosamente."""
        pagatore, ricevente = coppia_simulatori
        flusso = ResilientPaymentFlow()

        with pytest.raises(ValueError):
            flusso.esegui_pagamento(pagatore, ricevente, importo=-100)

    def test_pagamento_importo_zero_solleva_errore(self, coppia_simulatori):
        """Un importo zero deve sollevare ValueError."""
        pagatore, ricevente = coppia_simulatori
        flusso = ResilientPaymentFlow()

        with pytest.raises(ValueError):
            flusso.esegui_pagamento(pagatore, ricevente, importo=0)

    def test_pagamenti_multipli_incrementano_contatore(self, coppia_simulatori):
        """Ogni pagamento deve incrementare il contatore del pagatore."""
        pagatore, ricevente = coppia_simulatori
        flusso = ResilientPaymentFlow()

        contatore_iniziale = pagatore.get_counter()

        flusso.esegui_pagamento(pagatore, ricevente, importo=1000)
        flusso.esegui_pagamento(pagatore, ricevente, importo=1000)

        contatore_finale = pagatore.get_counter()
        assert contatore_finale == contatore_iniziale + 2

    def test_rollback_simulato_su_credit_fallito(self):
        """
        Verifica il comportamento di rollback quando il credit fallisce.
        Questo test usa un mock del ricevente che simula un fallimento del credit.
        """
        class RiceventeFallace(SecureElementInterface):
            """Simulatore che fa sempre fallire credit()."""

            def __init__(self):
                self._balance = 5000

            def process_apdu(self, apdu_bytes):
                return b'\x90\x00'

            def get_balance(self):
                return self._balance

            def debit(self, amount):
                return False

            def credit(self, amount):
                return False  # Simula fallimento

            def get_counter(self):
                return 0

            def sign_transaction(self, data):
                return b''

            def verify_signature(self, data, signature, public_key):
                return True

            def get_certificate(self):
                return b'\x04' + b'\x00' * 64

        pagatore = SecureElementSimulator(initial_balance=10000)
        ricevente = RiceventeFallace()
        flusso = ResilientPaymentFlow()

        saldo_prima = pagatore.get_balance()
        successo = flusso.esegui_pagamento(pagatore, ricevente, importo=2500)

        # Il pagamento deve fallire
        assert successo is False
        # Il saldo del pagatore deve essere ripristinato (rollback)
        assert pagatore.get_balance() == saldo_prima, \
            "Il rollback deve ripristinare il saldo del pagatore"


# =============================================================================
# TEST 6: Test hardware reali (saltati se non c'è lettore)
# =============================================================================

@pytest.mark.hardware
class TestHardwareConnection:
    """
    Test per la connessione al lettore ACR122U e alla smart card.

    ATTENZIONE: Questi test richiedono:
    1. Libreria pyscard installata: pip install pyscard
    2. Lettore ACR122U collegato via USB
    3. Smart card JCOP4 con applet AEGIS installato

    Vengono saltati automaticamente se il lettore non è disponibile.
    """

    def test_connessione_lettore(self, lettore_acr122u):
        """Verifica che il lettore sia rilevato e raggiungibile."""
        assert lettore_acr122u is not None
        assert str(lettore_acr122u)  # Il lettore deve avere un nome

    def test_creazione_hardware_se(self, lettore_acr122u):
        """Verifica la creazione di HardwareSecureElement con il lettore."""
        from host_app.python.hardware_se import HardwareSecureElement

        with HardwareSecureElement() as se:
            assert isinstance(se, SecureElementInterface)

    def test_select_applet_hardware(self, lettore_acr122u):
        """Verifica la selezione dell'applet AEGIS sulla carta reale."""
        from host_app.python.hardware_se import HardwareSecureElement

        with HardwareSecureElement() as se:
            apdu_select = bytes([0x00, 0xA4, 0x04, 0x00, 0x07,
                                 0xD2, 0x76, 0x00, 0x00, 0x60, 0x41, 0x01])
            risposta = se.process_apdu(apdu_select)
            sw = (risposta[-2] << 8) | risposta[-1]
            assert sw == 0x9000, f"SELECT deve restituire 0x9000, ottenuto 0x{sw:04X}"

    def test_get_balance_hardware(self, lettore_acr122u):
        """Verifica la lettura del saldo dalla carta reale."""
        from host_app.python.hardware_se import HardwareSecureElement

        with HardwareSecureElement() as se:
            saldo = se.get_balance()
            assert isinstance(saldo, int)
            assert saldo >= 0

    def test_debit_credit_hardware(self, lettore_acr122u):
        """
        Verifica un ciclo debit + credit sulla carta reale.

        NOTA: Questo test modifica il saldo della carta reale.
        Usa un importo piccolo (1 centesimo) per minimizzare l'impatto.
        """
        from host_app.python.hardware_se import HardwareSecureElement

        importo_test = 1  # 1 centesimo

        with HardwareSecureElement() as se:
            saldo_iniziale = se.get_balance()

            if saldo_iniziale < importo_test:
                pytest.skip(f"Saldo insufficiente per il test: {saldo_iniziale} centesimi")

            # Debit
            assert se.debit(importo_test) is True
            assert se.get_balance() == saldo_iniziale - importo_test

            # Credit (rimborso)
            assert se.credit(importo_test) is True
            assert se.get_balance() == saldo_iniziale

    def test_sign_hardware(self, lettore_acr122u):
        """Verifica la firma digitale sulla carta reale."""
        from host_app.python.hardware_se import HardwareSecureElement

        dati = b"dati_di_test_firma_hardware"

        with HardwareSecureElement() as se:
            firma = se.sign_transaction(dati)
            assert isinstance(firma, bytes)
            assert len(firma) > 0

            # Verifica la firma con la chiave pubblica della carta
            chiave_pubblica = se.get_certificate()
            assert se.verify_signature(dati, firma, chiave_pubblica) is True

    def test_factory_con_hardware(self, lettore_acr122u):
        """Verifica che la factory crei correttamente un HardwareSecureElement."""
        from host_app.python.hardware_se import HardwareSecureElement

        se = create_secure_element("pcscard")
        assert isinstance(se, HardwareSecureElement)
        assert isinstance(se, SecureElementInterface)

        if hasattr(se, 'disconnect'):
            se.disconnect()
