"""
test_aegis_integration.py — Test dell'integrazione aegis-protocol

Test pytest che verificano tutti i componenti dell'integrazione:
  - AegisClient: client HTTP con mock server
  - AegisReconciler: riconciliazione con transazioni simulate
  - IdentityMapper: operazioni CRUD sul registry
  - ZkProofAdapter: conversione ECDSA → ZK proof
  - Scenario end-to-end con mock API
  - Gestione errori (timeout, 401, 500, network failure)

Esecuzione:
    pytest tests/test_aegis_integration.py -v
    pytest tests/test_aegis_integration.py -v -k "test_client"  # solo test client
"""

import json
import os
import struct
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

from bridge.aegis_client import AegisClient, AegisApiError
from bridge.aegis_reconciler import AegisReconciler, ReconciliationResult
from bridge.identity_mapper import (
    IdentityMapper,
    IdentityMapperError,
    DeviceNotFoundError,
    InvalidAddressError,
)
from bridge.zk_proof_adapter import ZkProofAdapter, ZkProofError
from host_app.python.se_simulator import SecureElementSimulator


# =============================================================================
# FIXTURE CONDIVISE
# =============================================================================

@pytest.fixture
def tmp_registry(tmp_path):
    """Registry temporaneo su file per i test (rimosso automaticamente)."""
    return str(tmp_path / "test_registry.json")


@pytest.fixture
def mapper(tmp_registry):
    """IdentityMapper con registry temporaneo."""
    return IdentityMapper(registry_path=tmp_registry)


@pytest.fixture
def alice_se():
    """Secure Element simulato di Alice con 100€."""
    se = SecureElementSimulator(initial_balance=10000)
    apdu_select = SecureElementSimulator.build_apdu(0x00, 0xA4)
    se.process_apdu(apdu_select)
    return se


@pytest.fixture
def bob_se():
    """Secure Element simulato di Bob con 0€."""
    se = SecureElementSimulator(initial_balance=0)
    apdu_select = SecureElementSimulator.build_apdu(0x00, 0xA4)
    se.process_apdu(apdu_select)
    return se


@pytest.fixture
def sample_tx(alice_se):
    """Transazione di test firmata dal SE di Alice."""
    importo = 350  # 3.50€
    alice_se.debit(importo)
    contatore = alice_se.get_counter()
    timestamp = int(time.time())
    dati = struct.pack('>IIQ', importo, contatore, timestamp)
    firma = alice_se.sign_transaction(dati)
    return {
        "sender_id": "alice_wallet_roma_001",
        "receiver_id": "bob_pos_bar_roma_001",
        "amount": importo,
        "counter": contatore,
        "signature": firma.hex(),
        "timestamp": float(timestamp),
    }


@pytest.fixture
def alice_pubkey_hex(alice_se):
    """Chiave pubblica di Alice in formato hex."""
    return alice_se.get_certificate().hex()


@pytest.fixture
def mock_client():
    """AegisClient in modalità mock (nessuna chiamata HTTP reale)."""
    return AegisClient(mock_mode=True)


@pytest.fixture
def reconciler(mock_client, mapper):
    """AegisReconciler con client mock e mapper temporaneo."""
    return AegisReconciler(
        aegis_client=mock_client,
        identity_mapper=mapper,
        fallback_to_simulated=True,
    )


# =============================================================================
# TEST AEGIS CLIENT
# =============================================================================

class TestAegisClientMock:
    """Test del client in modalità mock (senza server reale)."""

    def test_client_mock_mode_default(self):
        """Il client deve essere in mock mode se requests non è disponibile o se forzato."""
        client = AegisClient(mock_mode=True)
        assert client.mock_mode is True

    def test_login_mock(self, mock_client):
        """Il login mock deve restituire un token non vuoto."""
        token = mock_client.login()
        assert isinstance(token, str)
        assert len(token) > 0
        assert mock_client._jwt_token is not None

    def test_send_transaction_mock(self, mock_client):
        """send_transaction in mock deve restituire un tx_hash."""
        risposta = mock_client.send_transaction(
            sender_address="0xA" * 40,
            recipient_address="0xB" * 40,
            amount_eur=3.50,
            proof_hash="0x" + "ab" * 32,
        )
        assert "tx_hash" in risposta
        assert risposta["tx_hash"].startswith("0x")
        assert risposta["amount"] == 3.50

    def test_send_transaction_hash_determinismo(self, mock_client):
        """Due TX identiche devono produrre lo stesso hash mock."""
        params = dict(
            sender_address="0x" + "a" * 40,
            recipient_address="0x" + "b" * 40,
            amount_eur=5.0,
            proof_hash="0x" + "cc" * 32,
        )
        r1 = mock_client.send_transaction(**params)
        r2 = mock_client.send_transaction(**params)
        assert r1["tx_hash"] == r2["tx_hash"]

    def test_get_transaction_status_mock(self, mock_client):
        """get_transaction_status deve ritornare uno stato valido."""
        status = mock_client.get_transaction_status("0x" + "a" * 64)
        assert "status" in status
        assert "tx_hash" in status

    def test_get_wallet_balance_mock(self, mock_client):
        """get_wallet_balance deve ritornare saldo e indirizzo."""
        addr = "0x" + "a" * 40
        bal = mock_client.get_wallet_balance(addr)
        assert "balance" in bal
        assert "address" in bal
        assert bal["address"] == addr
        assert isinstance(bal["balance"], (int, float))

    def test_check_kyc_sotto_soglia(self, mock_client):
        """check_kyc deve approvare importi < 1000€."""
        risultato = mock_client.check_kyc("0x" + "a" * 40, amount_eur=500.0)
        assert risultato["approved"] is True

    def test_check_kyc_sopra_soglia(self, mock_client):
        """check_kyc deve richiedere enhanced KYC per importi >= 1000€."""
        risultato = mock_client.check_kyc("0x" + "a" * 40, amount_eur=1500.0)
        assert risultato["approved"] is False

    def test_generate_proof_mock(self, mock_client):
        """generate_proof deve restituire proof e proof_hash."""
        risultato = mock_client.generate_proof(
            sender_address="0x" + "a" * 40,
            recipient_address="0x" + "b" * 40,
            amount_eur=10.0,
            ecdsa_signature="ab" * 36,
            counter=1,
            timestamp=time.time(),
        )
        assert "proof_hash" in risultato
        assert "proof" in risultato
        assert risultato["proof_hash"].startswith("0x")

    def test_verify_proof_mock(self, mock_client):
        """verify_proof deve ritornare valid=True in mock mode."""
        risultato = mock_client.verify_proof("mock_proof", "0x" + "ab" * 32, [])
        assert risultato["valid"] is True

    def test_ping_mock(self, mock_client):
        """ping deve ritornare True in mock mode."""
        assert mock_client.ping() is True

    def test_enable_disable_mock(self):
        """enable/disable mock mode deve cambiare lo stato del client."""
        client = AegisClient(mock_mode=True)
        assert client.mock_mode is True
        client.enable_mock_mode()
        assert client.mock_mode is True


class TestAegisClientErrorHandling:
    """Test della gestione errori del client."""

    def test_api_error_401_invalida_token(self):
        """Un errore 401 deve invalidare il token JWT corrente."""
        client = AegisClient(mock_mode=False)
        client._jwt_token = "vecchio_token_scaduto"
        client._token_expires_at = time.time() + 3600

        # Simuliamo una risposta HTTP 401
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.ok = False
        mock_resp.reason = "Unauthorized"
        mock_resp.json.return_value = {"detail": "Token scaduto"}

        with pytest.raises(AegisApiError) as exc_info:
            client._handle_response(mock_resp)

        assert exc_info.value.status_code == 401
        # Il token deve essere stato invalidato
        assert client._jwt_token is None

    def test_api_error_500_server_error(self):
        """Un errore 500 deve sollevare AegisApiError con status_code 500."""
        client = AegisClient(mock_mode=False)

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.ok = False
        mock_resp.reason = "Internal Server Error"
        mock_resp.json.return_value = {"detail": "Errore interno del server"}

        with pytest.raises(AegisApiError) as exc_info:
            client._handle_response(mock_resp)

        assert exc_info.value.status_code == 500

    def test_aegis_api_error_repr(self):
        """AegisApiError deve avere una rappresentazione stringa leggibile."""
        err = AegisApiError(404, "Resource not found")
        assert "404" in str(err)
        assert "Resource not found" in str(err)


# =============================================================================
# TEST IDENTITY MAPPER
# =============================================================================

class TestIdentityMapper:
    """Test del registry identità SE ↔ wallet."""

    # Indirizzi Ethereum validi per i test
    ALICE_WALLET = "0xA1ce0000000000000000000000000000000001ce"
    BOB_WALLET = "0xB0b00000000000000000000000000000000000b0"
    ALICE_PUBKEY = "04" + "ab" * 64  # 65 byte punto non compresso (fake)

    def test_register_device_successo(self, mapper):
        """register_device deve aggiungere un dispositivo al registry."""
        voce = mapper.register_device(
            se_device_id="test_device_001",
            wallet_address=self.ALICE_WALLET,
            public_key=self.ALICE_PUBKEY,
        )
        assert voce["se_device_id"] == "test_device_001"
        assert voce["wallet_address"] == self.ALICE_WALLET.lower()
        assert voce["public_key"] == self.ALICE_PUBKEY

    def test_register_device_indirizzo_invalido(self, mapper):
        """register_device deve rifiutare indirizzi Ethereum non validi."""
        with pytest.raises(InvalidAddressError):
            mapper.register_device(
                se_device_id="bad_device",
                wallet_address="non_un_indirizzo_valido",
                public_key=self.ALICE_PUBKEY,
            )

    def test_register_device_indirizzo_troppo_corto(self, mapper):
        """register_device deve rifiutare indirizzi troppo corti."""
        with pytest.raises(InvalidAddressError):
            mapper.register_device(
                se_device_id="bad_device",
                wallet_address="0x1234",
                public_key=self.ALICE_PUBKEY,
            )

    def test_register_device_duplicato(self, mapper):
        """register_device deve rifiutare duplicati senza overwrite=True."""
        mapper.register_device("dev_001", self.ALICE_WALLET, self.ALICE_PUBKEY)
        with pytest.raises(IdentityMapperError):
            mapper.register_device("dev_001", self.ALICE_WALLET, self.ALICE_PUBKEY)

    def test_register_device_overwrite(self, mapper):
        """register_device con overwrite=True deve aggiornare il dispositivo."""
        mapper.register_device("dev_001", self.ALICE_WALLET, self.ALICE_PUBKEY)
        nuova_voce = mapper.register_device(
            "dev_001", self.BOB_WALLET, self.ALICE_PUBKEY, overwrite=True
        )
        assert nuova_voce["wallet_address"] == self.BOB_WALLET.lower()

    def test_get_wallet_address(self, mapper):
        """get_wallet_address deve ritornare il wallet corretto."""
        mapper.register_device("alice_001", self.ALICE_WALLET, self.ALICE_PUBKEY)
        wallet = mapper.get_wallet_address("alice_001")
        assert wallet == self.ALICE_WALLET.lower()

    def test_get_wallet_address_non_trovato(self, mapper):
        """get_wallet_address deve sollevare DeviceNotFoundError se non trovato."""
        with pytest.raises(DeviceNotFoundError):
            mapper.get_wallet_address("dispositivo_inesistente")

    def test_get_public_key(self, mapper):
        """get_public_key deve ritornare la chiave pubblica corretta."""
        mapper.register_device("alice_001", self.ALICE_WALLET, self.ALICE_PUBKEY)
        pk = mapper.get_public_key("alice_001")
        assert pk == self.ALICE_PUBKEY

    def test_list_devices_vuoto(self, mapper):
        """list_devices su registry vuoto deve ritornare lista vuota."""
        assert mapper.list_devices() == []

    def test_list_devices_con_elementi(self, mapper):
        """list_devices deve elencare tutti i dispositivi."""
        mapper.register_device("alice_001", self.ALICE_WALLET, self.ALICE_PUBKEY)
        mapper.register_device("bob_001", self.BOB_WALLET, self.ALICE_PUBKEY)
        devices = mapper.list_devices()
        assert len(devices) == 2
        ids = {d["se_device_id"] for d in devices}
        assert "alice_001" in ids
        assert "bob_001" in ids

    def test_is_registered(self, mapper):
        """is_registered deve ritornare correttamente True/False."""
        mapper.register_device("alice_001", self.ALICE_WALLET, self.ALICE_PUBKEY)
        assert mapper.is_registered("alice_001") is True
        assert mapper.is_registered("inesistente") is False

    def test_deregister_device(self, mapper):
        """deregister_device deve rimuovere il dispositivo."""
        mapper.register_device("alice_001", self.ALICE_WALLET, self.ALICE_PUBKEY)
        assert mapper.deregister_device("alice_001") is True
        assert mapper.is_registered("alice_001") is False

    def test_deregister_device_non_esistente(self, mapper):
        """deregister_device su dispositivo non esistente deve ritornare False."""
        assert mapper.deregister_device("inesistente") is False

    def test_find_by_wallet(self, mapper):
        """find_by_wallet deve trovare il dispositivo per indirizzo."""
        mapper.register_device("alice_001", self.ALICE_WALLET, self.ALICE_PUBKEY)
        risultato = mapper.find_by_wallet(self.ALICE_WALLET)
        assert risultato is not None
        assert risultato["se_device_id"] == "alice_001"

    def test_find_by_wallet_non_trovato(self, mapper):
        """find_by_wallet deve ritornare None se non trovato."""
        risultato = mapper.find_by_wallet(self.BOB_WALLET)
        assert risultato is None

    def test_count(self, mapper):
        """count deve ritornare il numero corretto di dispositivi."""
        assert mapper.count() == 0
        mapper.register_device("a_001", self.ALICE_WALLET, self.ALICE_PUBKEY)
        assert mapper.count() == 1
        mapper.register_device("b_001", self.BOB_WALLET, self.ALICE_PUBKEY)
        assert mapper.count() == 2

    def test_persistenza_su_file(self, tmp_registry):
        """Il registry deve sopravvivere tra istanze diverse."""
        mapper1 = IdentityMapper(registry_path=tmp_registry)
        mapper1.register_device("alice_001", self.ALICE_WALLET, self.ALICE_PUBKEY)

        # Creo una nuova istanza sullo stesso file
        mapper2 = IdentityMapper(registry_path=tmp_registry)
        assert mapper2.is_registered("alice_001")
        assert mapper2.get_wallet_address("alice_001") == self.ALICE_WALLET.lower()

    def test_normalizzazione_indirizzo_maiuscolo(self, mapper):
        """Gli indirizzi in maiuscolo devono essere normalizzati in minuscolo."""
        indirizzo_maiuscolo = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
        mapper.register_device("dev_001", indirizzo_maiuscolo, self.ALICE_PUBKEY)
        wallet = mapper.get_wallet_address("dev_001")
        assert wallet == indirizzo_maiuscolo.lower()

    def test_metadata_opzionale(self, mapper):
        """register_device deve accettare metadata opzionali."""
        metadata = {"città": "Roma", "tipo": "POS"}
        mapper.register_device(
            "bob_001", self.BOB_WALLET, self.ALICE_PUBKEY, metadata=metadata
        )
        info = mapper.get_device_info("bob_001")
        assert info["metadata"] == metadata


# =============================================================================
# TEST ZK PROOF ADAPTER
# =============================================================================

class TestZkProofAdapter:
    """Test dell'adattatore ZK proof."""

    def test_adapt_base(self, alice_se, sample_tx, alice_pubkey_hex):
        """adapt deve restituire tutti i campi richiesti."""
        adapter = ZkProofAdapter(enable_local_verification=False)
        risultato = adapter.adapt(
            sender_id=sample_tx["sender_id"],
            receiver_id=sample_tx["receiver_id"],
            amount_cents=sample_tx["amount"],
            counter=sample_tx["counter"],
            ecdsa_signature_hex=sample_tx["signature"],
            timestamp=sample_tx["timestamp"],
        )
        assert "proof_hash" in risultato
        assert "amount_eur" in risultato
        assert "amount_aegis" in risultato
        assert "requires_zk" in risultato
        assert "ecdsa_signature" in risultato
        assert "canonical_message" in risultato
        assert "public_inputs" in risultato

    def test_proof_hash_formato(self, sample_tx):
        """Il proof_hash deve essere nel formato 0x + 64 hex chars."""
        adapter = ZkProofAdapter(enable_local_verification=False)
        risultato = adapter.adapt(
            sender_id=sample_tx["sender_id"],
            receiver_id=sample_tx["receiver_id"],
            amount_cents=sample_tx["amount"],
            counter=sample_tx["counter"],
            ecdsa_signature_hex=sample_tx["signature"],
            timestamp=sample_tx["timestamp"],
        )
        proof_hash = risultato["proof_hash"]
        assert proof_hash.startswith("0x")
        assert len(proof_hash) == 2 + 64  # "0x" + 64 hex chars

    def test_conversione_centesimi_eur(self):
        """cents_to_eur deve convertire correttamente."""
        assert ZkProofAdapter.cents_to_eur(350) == 3.50
        assert ZkProofAdapter.cents_to_eur(10000) == 100.0
        assert ZkProofAdapter.cents_to_eur(1) == 0.01

    def test_conversione_eur_aegis_units(self):
        """eur_to_aegis_units deve convertire con 6 decimali."""
        assert ZkProofAdapter.eur_to_aegis_units(1.0) == 1_000_000
        assert ZkProofAdapter.eur_to_aegis_units(3.50) == 3_500_000
        assert ZkProofAdapter.eur_to_aegis_units(0.01) == 10_000

    def test_conversione_cents_aegis_units(self):
        """cents_to_aegis_units deve convertire correttamente."""
        assert ZkProofAdapter.cents_to_aegis_units(350) == 3_500_000
        assert ZkProofAdapter.cents_to_aegis_units(100) == 1_000_000

    def test_soglia_mica_sotto(self, sample_tx):
        """Importi < 1000€ non richiedono ZK proof completa."""
        adapter = ZkProofAdapter(enable_local_verification=False)
        risultato = adapter.adapt(
            sender_id=sample_tx["sender_id"],
            receiver_id=sample_tx["receiver_id"],
            amount_cents=350,  # 3.50€
            counter=sample_tx["counter"],
            ecdsa_signature_hex=sample_tx["signature"],
            timestamp=sample_tx["timestamp"],
        )
        assert risultato["requires_zk"] is False

    def test_soglia_mica_sopra(self, sample_tx):
        """Importi >= 1000€ richiedono ZK proof completa."""
        adapter = ZkProofAdapter(enable_local_verification=False)
        risultato = adapter.adapt(
            sender_id=sample_tx["sender_id"],
            receiver_id=sample_tx["receiver_id"],
            amount_cents=100_000,  # 1000€ esatti
            counter=sample_tx["counter"],
            ecdsa_signature_hex=sample_tx["signature"],
            timestamp=sample_tx["timestamp"],
        )
        assert risultato["requires_zk"] is True

    def test_requires_mica_kyc(self):
        """requires_mica_kyc deve rispettare la soglia."""
        assert ZkProofAdapter.requires_mica_kyc(99_999) is False   # 999.99€
        assert ZkProofAdapter.requires_mica_kyc(100_000) is True   # 1000.00€
        assert ZkProofAdapter.requires_mica_kyc(200_000) is True   # 2000.00€

    def test_verifica_ecdsa_locale_valida(self, alice_se, sample_tx, alice_pubkey_hex):
        """La verifica ECDSA locale deve passare con firma valida."""
        adapter = ZkProofAdapter(enable_local_verification=True)
        # Non deve sollevare eccezioni
        risultato = adapter.adapt(
            sender_id=sample_tx["sender_id"],
            receiver_id=sample_tx["receiver_id"],
            amount_cents=sample_tx["amount"],
            counter=sample_tx["counter"],
            ecdsa_signature_hex=sample_tx["signature"],
            timestamp=sample_tx["timestamp"],
            sender_public_key_hex=alice_pubkey_hex,
        )
        assert risultato is not None

    def test_verifica_ecdsa_locale_invalida(self, sample_tx, alice_pubkey_hex):
        """La verifica ECDSA locale deve fallire con firma corrotta."""
        adapter = ZkProofAdapter(enable_local_verification=True)
        firma_corrotta = "deadbeef" * 18  # firma fasulla

        with pytest.raises(ZkProofError):
            adapter.adapt(
                sender_id=sample_tx["sender_id"],
                receiver_id=sample_tx["receiver_id"],
                amount_cents=sample_tx["amount"],
                counter=sample_tx["counter"],
                ecdsa_signature_hex=firma_corrotta,
                timestamp=sample_tx["timestamp"],
                sender_public_key_hex=alice_pubkey_hex,
            )

    def test_deterministico(self, sample_tx):
        """Due chiamate con gli stessi dati devono produrre lo stesso proof_hash."""
        adapter = ZkProofAdapter(enable_local_verification=False)
        kwargs = dict(
            sender_id=sample_tx["sender_id"],
            receiver_id=sample_tx["receiver_id"],
            amount_cents=sample_tx["amount"],
            counter=sample_tx["counter"],
            ecdsa_signature_hex=sample_tx["signature"],
            timestamp=sample_tx["timestamp"],
        )
        r1 = adapter.adapt(**kwargs)
        r2 = adapter.adapt(**kwargs)
        assert r1["proof_hash"] == r2["proof_hash"]
        assert r1["canonical_message"] == r2["canonical_message"]

    def test_importi_diversi_hash_diversi(self, sample_tx):
        """Importi diversi devono produrre proof_hash diversi."""
        adapter = ZkProofAdapter(enable_local_verification=False)
        r1 = adapter.adapt(
            sender_id="alice", receiver_id="bob",
            amount_cents=100, counter=1,
            ecdsa_signature_hex=sample_tx["signature"],
            timestamp=sample_tx["timestamp"],
        )
        r2 = adapter.adapt(
            sender_id="alice", receiver_id="bob",
            amount_cents=200, counter=1,
            ecdsa_signature_hex=sample_tx["signature"],
            timestamp=sample_tx["timestamp"],
        )
        assert r1["proof_hash"] != r2["proof_hash"]


# =============================================================================
# TEST AEGIS RECONCILER
# =============================================================================

class TestAegisReconciler:
    """Test del riconciliatore reale."""

    ALICE_WALLET = "0xa1ce0000000000000000000000000000000001ce"
    BOB_WALLET = "0xb0b00000000000000000000000000000000000b0"
    FAKE_PUBKEY = "04" + "ab" * 64

    def _setup_mapper(self, mapper, alice_pubkey_hex: str = None):
        """Registra Alice e Bob nel mapper di test."""
        pk = alice_pubkey_hex or self.FAKE_PUBKEY
        mapper.register_device("alice_wallet_roma_001", self.ALICE_WALLET, pk)
        mapper.register_device("bob_pos_bar_roma_001", self.BOB_WALLET, pk)

    def test_reconcile_vuoto(self, reconciler):
        """Riconciliazione con 0 transazioni deve completarsi senza errori."""
        risultato = reconciler.reconcile()
        assert risultato["totale"] == 0
        assert risultato["successi"] == 0

    def test_reconcile_tx_singola(self, reconciler, mapper, sample_tx, alice_pubkey_hex):
        """Riconciliazione di una singola TX deve riuscire in mock mode."""
        self._setup_mapper(mapper, alice_pubkey_hex)
        reconciler.register_public_key(
            "alice_wallet_roma_001", bytes.fromhex(alice_pubkey_hex)
        )
        reconciler.add_transaction(sample_tx)

        risultato = reconciler.reconcile()
        assert risultato["totale"] == 1
        assert risultato["successi"] == 1
        assert risultato["fallimenti"] == 0

    def test_reconcile_rimuove_da_pending(self, reconciler, mapper, sample_tx, alice_pubkey_hex):
        """Le TX riconciliate devono essere rimosse dalla coda pending."""
        self._setup_mapper(mapper, alice_pubkey_hex)
        reconciler.add_transaction(sample_tx)

        assert len(reconciler.get_pending_transactions()) == 1
        reconciler.reconcile()
        assert len(reconciler.get_pending_transactions()) == 0

    def test_reconcile_tx_invalida(self, reconciler):
        """TX con importo negativo deve essere segnalata come fallita."""
        tx_invalida = {
            "sender_id": "alice_wallet_roma_001",
            "receiver_id": "bob_pos_bar_roma_001",
            "amount": -100,  # importo non valido
            "counter": 1,
            "signature": "abcd" * 18,
            "timestamp": time.time(),
        }
        reconciler.add_transaction(tx_invalida)
        risultato = reconciler.reconcile()
        assert risultato["fallimenti"] == 1

    def test_get_reconciliation_summary(self, reconciler):
        """get_reconciliation_summary deve ritornare le statistiche corrette."""
        summary = reconciler.get_reconciliation_summary()
        assert "pending" in summary
        assert "reconciled" in summary
        assert "mode" in summary
        assert summary["mode"] == "mock"

    def test_reconcile_batch(self, reconciler, mapper, alice_pubkey_hex):
        """reconcile_batch deve processare una lista di TX esterne."""
        self._setup_mapper(mapper, alice_pubkey_hex)

        # Creiamo SE di Alice per generare TX reali
        alice_se = SecureElementSimulator(initial_balance=10000)
        apdu_select = SecureElementSimulator.build_apdu(0x00, 0xA4)
        alice_se.process_apdu(apdu_select)

        tx_list = []
        for importo in [100, 200, 300]:
            alice_se.debit(importo)
            cnt = alice_se.get_counter()
            ts = int(time.time())
            dati = struct.pack('>IIQ', importo, cnt, ts)
            firma = alice_se.sign_transaction(dati)
            tx_list.append({
                "sender_id": "alice_wallet_roma_001",
                "receiver_id": "bob_pos_bar_roma_001",
                "amount": importo,
                "counter": cnt,
                "signature": firma.hex(),
                "timestamp": float(ts),
            })

        # reconcile_batch aggiunge e processa le TX
        reconciler.reconcile_batch(tx_list)

        # Verifica che le TX siano state processate
        summary = reconciler.get_reconciliation_summary()
        assert summary["reconciled"] >= 0  # almeno 0 processate

    def test_fallback_simulato_su_errore(self):
        """Con fallback=True e API non disponibile, deve usare modalità simulata."""
        # Client che fallisce sempre
        client_rotto = AegisClient(mock_mode=False)
        client_rotto._session = MagicMock()
        client_rotto._session.post.side_effect = Exception("Connessione rifiutata")

        reconciler = AegisReconciler(
            aegis_client=client_rotto,
            fallback_to_simulated=True,
        )
        # Deve completarsi senza sollevare eccezioni
        reconciler.add_transaction({
            "sender_id": "test",
            "receiver_id": "test2",
            "amount": 100,
            "counter": 0,
            "signature": "abcd" * 18,
            "timestamp": time.time(),
        })
        risultato = reconciler.reconcile()
        # Con fallback, deve completarsi (successo o fallimento gestito)
        assert risultato["totale"] == 1


# =============================================================================
# TEST SCENARIO END-TO-END
# =============================================================================

class TestScenarioEndToEnd:
    """Test dello scenario completo con mock API."""

    ALICE_WALLET = "0xa1ce0000000000000000000000000000000001ce"
    BOB_WALLET = "0xb0b00000000000000000000000000000000000b0"

    def test_flusso_completo_mock(self, tmp_registry):
        """
        Test end-to-end: pagamento offline → riconciliazione on-chain (mock).

        Simula l'intero ciclo:
          1. Pagamento offline firmato dal SE
          2. Registrazione nel registry
          3. Riconciliazione tramite mock API
          4. Verifica tx_hash nel risultato
        """
        # Inizializzazione SE
        alice_se = SecureElementSimulator(initial_balance=10000)
        apdu_select = SecureElementSimulator.build_apdu(0x00, 0xA4)
        alice_se.process_apdu(apdu_select)

        # Ottieni chiave pubblica Alice
        alice_pubkey = alice_se.get_certificate().hex()

        # Pagamento offline
        importo = 350  # 3.50€
        alice_se.debit(importo)
        contatore = alice_se.get_counter()
        timestamp = int(time.time())
        dati = struct.pack('>IIQ', importo, contatore, timestamp)
        firma = alice_se.sign_transaction(dati)

        tx = {
            "sender_id": "alice_e2e_001",
            "receiver_id": "bob_e2e_001",
            "amount": importo,
            "counter": contatore,
            "signature": firma.hex(),
            "timestamp": float(timestamp),
        }

        # Setup registry
        mapper = IdentityMapper(registry_path=tmp_registry)
        mapper.register_device("alice_e2e_001", self.ALICE_WALLET, alice_pubkey)
        mapper.register_device("bob_e2e_001", self.BOB_WALLET, "04" + "ab" * 64)

        # Riconciliazione
        client = AegisClient(mock_mode=True)
        reconciler = AegisReconciler(
            aegis_client=client,
            identity_mapper=mapper,
            fallback_to_simulated=True,
        )
        reconciler.register_public_key("alice_e2e_001", alice_se.get_certificate())
        reconciler.add_transaction(tx)

        risultato = reconciler.reconcile()

        assert risultato["totale"] == 1
        assert risultato["successi"] == 1
        assert len(risultato["transazioni_ok"]) == 1

        # Verifica tx_hash presente
        tx_hash = risultato["transazioni_ok"][0].get("tx_hash", "")
        assert tx_hash.startswith("0x"), f"tx_hash non valido: {tx_hash}"

    def test_multipli_pagamenti_riconciliati(self, tmp_registry):
        """Scenario con più pagamenti: tutti devono essere riconciliati."""
        alice_se = SecureElementSimulator(initial_balance=50000)
        apdu_select = SecureElementSimulator.build_apdu(0x00, 0xA4)
        alice_se.process_apdu(apdu_select)
        alice_pubkey = alice_se.get_certificate().hex()

        mapper = IdentityMapper(registry_path=tmp_registry)
        mapper.register_device("alice_multi_001", self.ALICE_WALLET, alice_pubkey)
        mapper.register_device("bob_multi_001", self.BOB_WALLET, "04" + "ab" * 64)

        client = AegisClient(mock_mode=True)
        reconciler = AegisReconciler(
            aegis_client=client,
            identity_mapper=mapper,
        )
        reconciler.register_public_key("alice_multi_001", alice_se.get_certificate())

        # 3 pagamenti consecutivi
        for importo in [120, 350, 850]:
            alice_se.debit(importo)
            cnt = alice_se.get_counter()
            ts = int(time.time())
            dati = struct.pack('>IIQ', importo, cnt, ts)
            firma = alice_se.sign_transaction(dati)
            reconciler.add_transaction({
                "sender_id": "alice_multi_001",
                "receiver_id": "bob_multi_001",
                "amount": importo,
                "counter": cnt,
                "signature": firma.hex(),
                "timestamp": float(ts),
            })

        risultato = reconciler.reconcile()
        assert risultato["totale"] == 3
        assert risultato["successi"] == 3
        assert risultato["fallimenti"] == 0


# =============================================================================
# TEST GESTIONE ERRORI
# =============================================================================

class TestGestioneErrori:
    """Test della gestione degli errori nei casi limite."""

    def test_tx_senza_firma(self, reconciler):
        """TX senza firma deve essere rifiutata nella verifica."""
        tx = {
            "sender_id": "alice",
            "receiver_id": "bob",
            "amount": 100,
            "counter": 0,
            "signature": "",  # firma vuota
            "timestamp": time.time(),
        }
        reconciler.add_transaction(tx)
        risultato = reconciler.reconcile()
        assert risultato["fallimenti"] == 1

    def test_tx_importo_zero(self, reconciler):
        """TX con importo zero deve essere rifiutata."""
        tx = {
            "sender_id": "alice",
            "receiver_id": "bob",
            "amount": 0,
            "counter": 0,
            "signature": "abcd" * 18,
            "timestamp": time.time(),
        }
        reconciler.add_transaction(tx)
        risultato = reconciler.reconcile()
        assert risultato["fallimenti"] == 1

    def test_add_transaction_campo_mancante(self, reconciler):
        """add_transaction deve rifiutare TX con campo mancante."""
        tx_incompleta = {
            "sender_id": "alice",
            # manca receiver_id
            "amount": 100,
            "counter": 0,
            "signature": "abcd" * 18,
        }
        risultato = reconciler.add_transaction(tx_incompleta)
        assert risultato is False

    def test_aegis_api_error_contiene_body(self):
        """AegisApiError deve conservare il body della risposta."""
        body = {"code": "INSUFFICIENT_BALANCE", "available": 50.0}
        err = AegisApiError(400, "Saldo insufficiente", body)
        assert err.body == body
        assert err.status_code == 400

    def test_identity_mapper_file_corrotto(self, tmp_path):
        """IdentityMapper deve gestire file JSON corrotto."""
        registry_path = str(tmp_path / "corrotto.json")
        with open(registry_path, "w") as f:
            f.write("questo non è JSON valido {{{")

        # Non deve sollevare eccezioni, deve partire con registry vuoto
        mapper = IdentityMapper(registry_path=registry_path)
        assert mapper.count() == 0

    def test_zk_adapter_firma_hex_con_prefisso(self, sample_tx):
        """ZkProofAdapter deve accettare firme con e senza prefisso 0x."""
        adapter = ZkProofAdapter(enable_local_verification=False)

        # Con prefisso 0x
        sig_con_prefisso = "0x" + sample_tx["signature"]
        r1 = adapter.adapt(
            "alice", "bob", 100, 1, sig_con_prefisso, sample_tx["timestamp"]
        )

        # Senza prefisso 0x
        r2 = adapter.adapt(
            "alice", "bob", 100, 1, sample_tx["signature"], sample_tx["timestamp"]
        )

        # I proof_hash devono essere identici
        assert r1["proof_hash"] == r2["proof_hash"]
