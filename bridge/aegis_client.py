"""
aegis_client.py — Client HTTP per le REST API di aegis-protocol

Questo modulo implementa un client Python che wrappa tutte le chiamate
REST API di aegis-protocol necessarie per la riconciliazione on-chain.
Funziona come un "interprete" tra il mondo offline del Secure Element
e il backend blockchain di aegis-protocol.

Funzionalità principali:
- Autenticazione JWT con refresh automatico
- Retry con backoff esponenziale in caso di errori temporanei
- Modalità dev/mock quando aegis-protocol non è raggiungibile
- Type hints completi e docstring in italiano

Endpoint supportati (da aegis-protocol/main_app.py):
    POST /auth/login              → autenticazione JWT
    POST /transactions/send       → invio transazione on-chain
    GET  /transactions/{tx}/status → verifica stato TX
    GET  /wallet/balance/{addr}   → query saldo on-chain
    POST /compliance/kyc          → verifica KYC
    GET  /compliance/profile      → profilo compliance
    POST /proof/generate          → generazione ZK proof
    POST /proof/verify            → verifica ZK proof
"""

import hashlib
import logging
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Importazione opzionale di requests: se non disponibile si usa solo mock mode
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
    logger.warning("⚠️  Libreria 'requests' non disponibile — solo modalità mock attiva")


# =============================================================================
# COSTANTI
# =============================================================================

# Timeout di default per le richieste HTTP (in secondi)
DEFAULT_TIMEOUT: int = 30

# Numero massimo di tentativi in caso di errore
DEFAULT_MAX_RETRIES: int = 3

# Fattore di backoff esponenziale tra i tentativi (in secondi)
DEFAULT_BACKOFF_FACTOR: float = 0.5

# Codici HTTP che giustificano un retry automatico
RETRY_STATUS_CODES: tuple[int, ...] = (429, 500, 502, 503, 504)

# Soglia MiCA: 1000€ (in centesimi) — sopra questa soglia serve KYC
MICA_KYC_THRESHOLD_CENTS: int = 100_000  # 1000 * 100 centesimi


class AegisApiError(Exception):
    """
    Eccezione per errori dell'API aegis-protocol.

    Come una risposta di errore dal banco della banca:
    include il codice di stato HTTP e il messaggio di dettaglio.
    """

    def __init__(self, status_code: int, message: str, body: Optional[dict] = None):
        self.status_code = status_code
        self.message = message
        self.body = body or {}
        super().__init__(f"AegisAPI {status_code}: {message}")


class AegisClient:
    """
    Client HTTP per le REST API di aegis-protocol.

    Questo client gestisce tutta la comunicazione con il backend blockchain:
    autenticazione, invio transazioni, verifica stato, compliance e prove ZK.

    Funziona come un "agente di viaggio" specializzato:
    conosce tutti gli indirizzi (endpoint), gestisce i documenti (JWT token),
    e sa cosa fare quando qualcosa va storto (retry, fallback mock).

    Attributi:
        base_url: URL base dell'API aegis-protocol
        username: nome utente per l'autenticazione JWT
        password: password per l'autenticazione JWT
        timeout: timeout HTTP in secondi
        max_retries: numero massimo di tentativi
        mock_mode: se True, simula le risposte senza chiamate HTTP reali
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        username: str = "aegis_bridge",
        password: str = "bridge_secret",
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        mock_mode: bool = False,
    ):
        """
        Inizializza il client aegis-protocol.

        Parametri:
            base_url: URL base dell'API (es. "http://localhost:8000")
            username: username per autenticazione JWT
            password: password per autenticazione JWT
            timeout: timeout HTTP in secondi (default: 30)
            max_retries: tentativi massimi per richiesta (default: 3)
            backoff_factor: fattore backoff esponenziale (default: 0.5)
            mock_mode: se True, usa risposte simulate (utile per sviluppo)
        """
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

        # Modalità mock: attiva se richiesta esplicitamente o se requests non è disponibile
        self.mock_mode: bool = mock_mode or not _REQUESTS_AVAILABLE

        # Token JWT corrente e relativa scadenza
        self._jwt_token: Optional[str] = None
        self._token_expires_at: float = 0.0

        # Sessione HTTP con retry automatico
        self._session: Optional[Any] = None
        if not self.mock_mode and _REQUESTS_AVAILABLE:
            self._session = self._create_session()

        logger.info(
            "🔌 AegisClient inizializzato — URL: %s | Mock: %s",
            self.base_url,
            self.mock_mode,
        )

    # =========================================================================
    # SETUP SESSIONE HTTP
    # =========================================================================

    def _create_session(self) -> "requests.Session":
        """
        Crea una sessione HTTP con retry automatico e backoff esponenziale.

        Come aprire un canale di comunicazione affidabile:
        se la linea cade, riprova automaticamente fino a max_retries volte.
        """
        session = requests.Session()

        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=list(RETRY_STATUS_CODES),
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    # =========================================================================
    # AUTENTICAZIONE JWT
    # =========================================================================

    def login(self, username: Optional[str] = None, password: Optional[str] = None) -> str:
        """
        Autentica con aegis-protocol e ottiene un token JWT.

        Come presentare i propri documenti alla guardia all'ingresso:
        fornisci username e password, ricevi un "badge" temporaneo (JWT).

        Parametri:
            username: sovrascrive il valore di default
            password: sovrascrive il valore di default

        Ritorna:
            Token JWT come stringa

        Eccezioni:
            AegisApiError: se l'autenticazione fallisce
        """
        user = username or self.username
        pwd = password or self.password

        if self.mock_mode:
            logger.debug("🔐 [MOCK] Login simulato per: %s", user)
            self._jwt_token = "mock_jwt_token_development_only"
            self._token_expires_at = time.time() + 3600
            return self._jwt_token

        risposta = self._post("/auth/login", {"username": user, "password": pwd}, authed=False)
        token = risposta.get("access_token", "")
        if not token:
            raise AegisApiError(401, "Token JWT non ricevuto nella risposta")

        self._jwt_token = token
        # Scadenza stimata: 55 minuti (un po' meno di 1 ora per sicurezza)
        expires_in = risposta.get("expires_in", 3600)
        self._token_expires_at = time.time() + expires_in - 300
        logger.info("🔐 Autenticato come '%s' (scadenza fra %ds)", user, expires_in)
        return token

    def _ensure_authenticated(self) -> None:
        """
        Verifica che il token JWT sia valido e, se necessario, lo rinnova.

        Come controllare la scadenza del badge prima di entrare:
        se sta per scadere, vai a rinnovarlo prima di essere bloccato.
        """
        if not self._jwt_token or time.time() >= self._token_expires_at:
            logger.debug("🔄 Token JWT scaduto o assente — rinnovo in corso...")
            self.login()

    # =========================================================================
    # TRANSAZIONI
    # =========================================================================

    def send_transaction(
        self,
        sender_address: str,
        recipient_address: str,
        amount_eur: float,
        proof_hash: str,
        offline_counter: int = 0,
        offline_timestamp: Optional[float] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """
        Invia una transazione on-chain tramite aegis-protocol.

        Corrisponde a POST /transactions/send nell'API aegis-protocol.
        Trasferisce AegisEUR da mittente a destinatario con proof crittografica
        per la verifica su AegisEUR.sol (transferWithProof).

        Parametri:
            sender_address: wallet Ethereum del mittente (0x...)
            recipient_address: wallet Ethereum del destinatario (0x...)
            amount_eur: importo in EUR (float, es. 3.50 per 3.50€)
            proof_hash: hash della firma ECDSA come prova (hex string)
            offline_counter: valore del contatore monotònico del SE
            offline_timestamp: timestamp della transazione offline (epoch Unix)
            metadata: dati aggiuntivi opzionali per la transazione

        Ritorna:
            Dizionario con almeno: {"tx_hash": "0x...", "status": "pending"}

        Eccezioni:
            AegisApiError: se la transazione viene rifiutata dall'API
        """
        if self.mock_mode:
            tx_hash = "0x" + hashlib.sha256(
                f"{sender_address}{recipient_address}{amount_eur}{proof_hash}".encode()
            ).hexdigest()
            logger.debug(
                "💸 [MOCK] TX simulata: %s → %s: %.2f€ | hash: %s",
                sender_address, recipient_address, amount_eur, tx_hash
            )
            return {
                "tx_hash": tx_hash,
                "status": "mock_confirmed",
                "amount": amount_eur,
                "sender": sender_address,
                "recipient": recipient_address,
            }

        self._ensure_authenticated()
        payload: dict = {
            "sender_address": sender_address,
            "recipient_address": recipient_address,
            "amount": amount_eur,
            "proof_hash": proof_hash,
            "offline_counter": offline_counter,
            "offline_timestamp": offline_timestamp or time.time(),
        }
        if metadata:
            payload["metadata"] = metadata

        return self._post("/transactions/send", payload)

    def get_transaction_status(self, tx_hash: str) -> dict:
        """
        Verifica lo stato di una transazione on-chain.

        Corrisponde a GET /transactions/{tx_hash}/status.
        Come controllare lo stato di un pacco spedito:
        ti dice se è in transito, consegnato, o perso.

        Parametri:
            tx_hash: hash della transazione on-chain (0x...)

        Ritorna:
            Dizionario con status, block_number, confirmations, ecc.
        """
        if self.mock_mode:
            return {
                "tx_hash": tx_hash,
                "status": "mock_confirmed",
                "block_number": 99999,
                "confirmations": 12,
            }

        self._ensure_authenticated()
        return self._get(f"/transactions/{tx_hash}/status")

    # =========================================================================
    # WALLET
    # =========================================================================

    def get_wallet_balance(self, address: str) -> dict:
        """
        Interroga il saldo on-chain di un wallet AegisEUR.

        Corrisponde a GET /wallet/balance/{address}.
        Come controllare il saldo su internet banking:
        l'importo aggiornato è sempre quello sulla blockchain.

        Parametri:
            address: indirizzo Ethereum del wallet (0x + 40 hex chars)

        Ritorna:
            Dizionario con: {"address": "0x...", "balance": 1234.56, "token": "AegisEUR"}
        """
        if self.mock_mode:
            return {
                "address": address,
                "balance": 1000.0,
                "token": "AegisEUR",
                "chain_id": 80002,
                "mock": True,
            }

        self._ensure_authenticated()
        return self._get(f"/wallet/balance/{address}")

    # =========================================================================
    # COMPLIANCE
    # =========================================================================

    def check_kyc(self, address: str, amount_eur: float) -> dict:
        """
        Verifica KYC per una transazione (regola MiCA > 1000€).

        Corrisponde a POST /compliance/kyc.
        Come il controllo del documento d'identità in banca:
        obbligatorio per importi elevati secondo la normativa MiCA.

        Parametri:
            address: wallet address da verificare
            amount_eur: importo della transazione in EUR

        Ritorna:
            Dizionario con: {"approved": True/False, "level": "basic"|"enhanced", ...}
        """
        if self.mock_mode:
            approved = amount_eur < (MICA_KYC_THRESHOLD_CENTS / 100)
            return {
                "address": address,
                "approved": approved,
                "level": "basic" if approved else "enhanced_required",
                "mock": True,
            }

        self._ensure_authenticated()
        payload = {"address": address, "amount": amount_eur}
        return self._post("/compliance/kyc", payload)

    def get_compliance_profile(self, address: str) -> dict:
        """
        Recupera il profilo di compliance di un wallet.

        Corrisponde a GET /compliance/profile.

        Parametri:
            address: wallet address

        Ritorna:
            Profilo compliance con KYC level, velocity limit, ecc.
        """
        if self.mock_mode:
            return {
                "address": address,
                "kyc_level": "basic",
                "velocity_limit_daily": 10000.0,
                "velocity_used_today": 0.0,
                "mica_compliant": True,
                "mock": True,
            }

        self._ensure_authenticated()
        return self._get(f"/compliance/profile?address={address}")

    # =========================================================================
    # ZK PROOF
    # =========================================================================

    def generate_proof(
        self,
        sender_address: str,
        recipient_address: str,
        amount_eur: float,
        ecdsa_signature: str,
        counter: int,
        timestamp: float,
    ) -> dict:
        """
        Richiede ad aegis-protocol la generazione di una ZK proof Noir.

        Corrisponde a POST /proof/generate.
        Come commissionare a un notaio la preparazione di un documento
        che attesta la validità di una transazione senza rivelarne i dettagli.

        Parametri:
            sender_address: wallet Ethereum del mittente
            recipient_address: wallet Ethereum del destinatario
            amount_eur: importo in EUR
            ecdsa_signature: firma ECDSA della transazione (hex)
            counter: contatore monotònico del SE
            timestamp: timestamp della transazione (epoch Unix)

        Ritorna:
            Dizionario con: {"proof": "...", "proof_hash": "0x...", "public_inputs": [...]}
        """
        if self.mock_mode:
            proof_hash = "0x" + hashlib.sha256(
                f"{sender_address}{amount_eur}{ecdsa_signature}".encode()
            ).hexdigest()
            return {
                "proof": "mock_zk_proof_bytes",
                "proof_hash": proof_hash,
                "public_inputs": [sender_address, str(amount_eur)],
                "mock": True,
            }

        self._ensure_authenticated()
        payload = {
            "sender_address": sender_address,
            "recipient_address": recipient_address,
            "amount": amount_eur,
            "ecdsa_signature": ecdsa_signature,
            "counter": counter,
            "timestamp": timestamp,
        }
        return self._post("/proof/generate", payload)

    def verify_proof(self, proof: str, proof_hash: str, public_inputs: list) -> dict:
        """
        Verifica una ZK proof tramite aegis-protocol.

        Corrisponde a POST /proof/verify.

        Parametri:
            proof: bytes della proof (base64 o hex)
            proof_hash: hash della proof (keccak256)
            public_inputs: ingressi pubblici del circuito Noir

        Ritorna:
            Dizionario con: {"valid": True/False, "verified_at": timestamp}
        """
        if self.mock_mode:
            return {"valid": True, "verified_at": time.time(), "mock": True}

        self._ensure_authenticated()
        payload = {
            "proof": proof,
            "proof_hash": proof_hash,
            "public_inputs": public_inputs,
        }
        return self._post("/proof/verify", payload)

    # =========================================================================
    # METODI HTTP INTERNI
    # =========================================================================

    def _get(self, path: str) -> dict:
        """
        Esegue una richiesta GET autenticata all'API aegis-protocol.

        Parametri:
            path: percorso dell'endpoint (es. "/wallet/balance/0x...")

        Ritorna:
            Corpo della risposta come dizionario

        Eccezioni:
            AegisApiError: in caso di errore HTTP o di connessione
        """
        url = self.base_url + path
        headers = self._auth_headers()

        try:
            resp = self._session.get(url, headers=headers, timeout=self.timeout)
            return self._handle_response(resp)
        except AegisApiError:
            raise
        except Exception as exc:
            logger.error("❌ GET %s fallita: %s", path, exc)
            raise AegisApiError(0, f"Errore di connessione: {exc}") from exc

    def _post(self, path: str, payload: dict, authed: bool = True) -> dict:
        """
        Esegue una richiesta POST all'API aegis-protocol.

        Parametri:
            path: percorso dell'endpoint
            payload: corpo della richiesta (verrà serializzato come JSON)
            authed: se True, include il token JWT nell'header

        Ritorna:
            Corpo della risposta come dizionario

        Eccezioni:
            AegisApiError: in caso di errore HTTP o di connessione
        """
        url = self.base_url + path
        headers = self._auth_headers() if authed else {"Content-Type": "application/json"}

        try:
            resp = self._session.post(url, json=payload, headers=headers, timeout=self.timeout)
            return self._handle_response(resp)
        except AegisApiError:
            raise
        except Exception as exc:
            logger.error("❌ POST %s fallita: %s", path, exc)
            raise AegisApiError(0, f"Errore di connessione: {exc}") from exc

    def _auth_headers(self) -> dict:
        """Restituisce gli header HTTP con il token JWT."""
        headers: dict = {"Content-Type": "application/json"}
        if self._jwt_token:
            headers["Authorization"] = f"Bearer {self._jwt_token}"
        return headers

    def _handle_response(self, resp: Any) -> dict:
        """
        Interpreta la risposta HTTP e solleva AegisApiError in caso di errore.

        Come controllare la risposta del postino:
        se la lettera è tornata indietro (codice di errore),
        la gestisci in modo appropriato invece di ignorarla.

        Parametri:
            resp: oggetto Response di requests

        Ritorna:
            Corpo JSON della risposta come dizionario

        Eccezioni:
            AegisApiError: per tutti i codici HTTP != 2xx
        """
        if resp.status_code == 401:
            # Token scaduto: invalidiamo il token locale e segnaliamo l'errore
            self._jwt_token = None
            self._token_expires_at = 0.0
            raise AegisApiError(401, "Token JWT scaduto o non valido — ri-autenticazione necessaria")

        if not resp.ok:
            corpo: dict = {}
            try:
                corpo = resp.json()
            except Exception:
                corpo = {"raw": resp.text[:200]}
            messaggio = corpo.get("detail", corpo.get("message", resp.reason or "Errore sconosciuto"))
            raise AegisApiError(resp.status_code, messaggio, corpo)

        try:
            return resp.json()
        except Exception:
            # Risposta 2xx senza JSON (es. 204 No Content)
            return {"status": "ok", "status_code": resp.status_code}

    # =========================================================================
    # UTILITÀ
    # =========================================================================

    def ping(self) -> bool:
        """
        Verifica la raggiungibilità dell'API aegis-protocol.

        Come fare un "squillo" per sapere se qualcuno risponde.

        Ritorna:
            True se l'API risponde, False altrimenti
        """
        if self.mock_mode:
            return True
        try:
            resp = self._session.get(
                f"{self.base_url}/health",
                timeout=min(5, self.timeout),
            )
            return resp.ok
        except Exception:
            return False

    def enable_mock_mode(self) -> None:
        """Abilita la modalità mock (utile per fallback automatico)."""
        self.mock_mode = True
        logger.info("🔄 AegisClient: modalità mock attivata (aegis-protocol non raggiungibile)")

    def disable_mock_mode(self) -> None:
        """Disabilita la modalità mock."""
        if not _REQUESTS_AVAILABLE:
            logger.warning("⚠️  Impossibile disabilitare mock: 'requests' non disponibile")
            return
        self.mock_mode = False
        if not self._session:
            self._session = self._create_session()
        logger.info("🔌 AegisClient: modalità reale riattivata")

    def __repr__(self) -> str:
        return (
            f"AegisClient(url={self.base_url!r}, "
            f"mock={self.mock_mode}, "
            f"authed={bool(self._jwt_token)})"
        )
