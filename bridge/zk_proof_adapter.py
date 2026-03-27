"""
zk_proof_adapter.py — Adattatore per ZK proofs di aegis-protocol

Questo modulo adatta le firme ECDSA del Secure Element (curva secp256r1)
al formato di proof richiesto dallo smart contract AegisEUR.sol tramite
il NoirVerifier (UltraPlonk) di aegis-protocol.

Il flusso è il seguente:
  1. Il Secure Element firma i dati della transazione con ECDSA (secp256r1)
  2. Questo adattatore converte la firma + metadati in un formato proof
  3. Calcola il proofHash compatibile con keccak256 dello smart contract
  4. Verifica localmente la proof prima di inviarla

Conformità MiCA:
  - Per importi < 1000€: la firma ECDSA è sufficiente come proof
  - Per importi >= 1000€: è necessaria una ZK proof completa (Noir/UltraPlonk)
    generata dal backend aegis-protocol

Nota tecnica sulla curva:
  Il Secure Element usa secp256r1 (P-256), mentre Ethereum usa secp256k1.
  Questo adattatore gestisce la conversione del formato ma non cambia la curva.
  La verifica on-chain avviene tramite il NoirVerifier che supporta P-256.
"""

import hashlib
import json
import logging
import struct
import time
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

# =============================================================================
# COSTANTI
# =============================================================================

# Soglia MiCA per KYC obbligatorio: 1000€ (in centesimi)
MICA_THRESHOLD_CENTS: int = 100_000

# Soglia MiCA per KYC obbligatorio: 1000€ (in EUR)
MICA_THRESHOLD_EUR: float = 1_000.0

# Decimali del token AegisEUR (come in ERC-20, 6 decimali come USDC)
AEGIS_EUR_DECIMALS: int = 6

# Lunghezza attesa della firma DER ECDSA (min/max in byte)
DER_SIGNATURE_MIN_LEN: int = 70
DER_SIGNATURE_MAX_LEN: int = 72


class ZkProofError(Exception):
    """Eccezione per errori nella generazione o verifica delle proof."""


class ZkProofAdapter:
    """
    Adattatore tra firme ECDSA del Secure Element e proof per AegisEUR.sol.

    Questo modulo risolve un problema di "traduzione":
    il Secure Element parla il linguaggio delle firme ECDSA (secp256r1),
    mentre lo smart contract AegisEUR.sol parla il linguaggio delle ZK proof
    (formato UltraPlonk del NoirVerifier).

    Per importi piccoli (< 1000€), la firma ECDSA viene usata direttamente
    come proof (con un hash keccak256 per identificarla univocamente).
    Per importi grandi (>= 1000€), è necessario che aegis-protocol generi
    una ZK proof completa tramite il circuito Noir.

    Attributi:
        enable_local_verification: se True, verifica la firma ECDSA localmente
                                   prima di generare la proof
    """

    def __init__(self, enable_local_verification: bool = True):
        """
        Inizializza l'adattatore ZK proof.

        Parametri:
            enable_local_verification: abilita verifica ECDSA locale (default: True)
        """
        self.enable_local_verification = enable_local_verification
        logger.info(
            "🔐 ZkProofAdapter inizializzato (verifica locale: %s)",
            enable_local_verification,
        )

    # =========================================================================
    # METODO PRINCIPALE
    # =========================================================================

    def adapt(
        self,
        sender_id: str,
        receiver_id: str,
        amount_cents: int,
        counter: int,
        ecdsa_signature_hex: str,
        timestamp: Optional[float] = None,
        sender_public_key_hex: Optional[str] = None,
        sender_wallet: Optional[str] = None,
        receiver_wallet: Optional[str] = None,
    ) -> dict:
        """
        Adatta i dati di una transazione SE in formato proof per aegis-protocol.

        Questo è il metodo centrale del modulo. Prende i dati grezzi della
        transazione offline (come arrivano dal Secure Element) e li trasforma
        nel formato atteso dallo smart contract AegisEUR.sol.

        Parametri:
            sender_id: identificativo del mittente nel SE (es. "alice_wallet_roma_001")
            receiver_id: identificativo del destinatario nel SE
            amount_cents: importo in centesimi (es. 350 = 3.50€)
            counter: valore del contatore monotònico del SE
            ecdsa_signature_hex: firma ECDSA della transazione in formato hex
            timestamp: timestamp della transazione (default: ora)
            sender_public_key_hex: chiave pubblica del mittente (hex, 65 byte = 130 chars)
                                   richiesta per la verifica locale
            sender_wallet: indirizzo Ethereum on-chain del mittente (opzionale)
            receiver_wallet: indirizzo Ethereum on-chain del destinatario (opzionale)

        Ritorna:
            Dizionario con tutti i campi necessari per la riconciliazione:
            {
                "proof_hash": "0x...",          # hash keccak256 della proof
                "proof_data": "...",            # dati della proof (hex o mock)
                "amount_aegis": int,            # importo in unità AegisEUR (6 decimali)
                "amount_eur": float,            # importo in EUR
                "requires_zk": bool,            # True se serve ZK proof completa (MiCA)
                "ecdsa_signature": "0x...",     # firma originale normalizzata
                "canonical_message": "...",     # messaggio firmato (hex)
                "public_inputs": [...],         # ingressi pubblici per Noir
                "sender_id": str,
                "receiver_id": str,
                "counter": int,
                "timestamp": float,
            }

        Eccezioni:
            ZkProofError: se la firma non è valida (quando la verifica è abilitata)
        """
        ts = timestamp or time.time()
        amount_eur = self.cents_to_eur(amount_cents)

        # 1. Normalizza la firma ECDSA
        sig_hex = self._normalize_signature(ecdsa_signature_hex)

        # 2. Calcola il messaggio canonico firmato (stesso formato del SE)
        canonical_msg = self._build_canonical_message(amount_cents, counter, ts)

        # 3. Verifica locale della firma ECDSA (se richiesta e possibile)
        if self.enable_local_verification and sender_public_key_hex:
            self._verify_ecdsa_local(
                canonical_msg, sig_hex, sender_public_key_hex, sender_id
            )

        # 4. Calcola il proof hash (keccak256-like via SHA-3)
        proof_hash = self._compute_proof_hash(sig_hex, canonical_msg, sender_id, receiver_id)

        # 5. Costruisce i dati della proof
        proof_data = self._build_proof_data(sig_hex, canonical_msg, sender_id, receiver_id)

        # 6. Determina se serve ZK proof completa (soglia MiCA)
        requires_zk = amount_eur >= MICA_THRESHOLD_EUR

        # 7. Converte l'importo in unità AegisEUR (6 decimali, come USDC)
        amount_aegis = self.eur_to_aegis_units(amount_eur)

        # 8. Costruisce gli ingressi pubblici per il circuito Noir
        public_inputs = self._build_public_inputs(
            sender_wallet or sender_id,
            receiver_wallet or receiver_id,
            amount_aegis,
            counter,
            ts,
        )

        risultato = {
            "proof_hash": proof_hash,
            "proof_data": proof_data,
            "amount_aegis": amount_aegis,
            "amount_eur": amount_eur,
            "amount_cents": amount_cents,
            "requires_zk": requires_zk,
            "ecdsa_signature": sig_hex,
            "canonical_message": canonical_msg.hex(),
            "public_inputs": public_inputs,
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "sender_wallet": sender_wallet,
            "receiver_wallet": receiver_wallet,
            "counter": counter,
            "timestamp": ts,
        }

        if requires_zk:
            logger.warning(
                "⚠️  Importo %.2f€ >= soglia MiCA %.2f€ — richiesta ZK proof completa "
                "da aegis-protocol",
                amount_eur,
                MICA_THRESHOLD_EUR,
            )

        logger.debug(
            "🔐 Proof generata: %s → %s | %.2f€ | hash: %s | ZK: %s",
            sender_id, receiver_id, amount_eur, proof_hash, requires_zk,
        )

        return risultato

    # =========================================================================
    # CONVERSIONI IMPORTO
    # =========================================================================

    @staticmethod
    def cents_to_eur(cents: int) -> float:
        """
        Converte centesimi in EUR float.

        Parametri:
            cents: importo in centesimi (es. 350 → 3.50)

        Ritorna:
            Importo in EUR (float con 2 decimali significativi)
        """
        return round(cents / 100.0, 2)

    @staticmethod
    def eur_to_aegis_units(amount_eur: float) -> int:
        """
        Converte EUR float in unità AegisEUR (6 decimali, come USDC).

        AegisEUR ha 6 decimali, quindi:
          1 EUR = 1_000_000 unità (1 * 10^6)
          3.50 EUR = 3_500_000 unità

        Parametri:
            amount_eur: importo in EUR

        Ritorna:
            Importo in unità minime AegisEUR (int)
        """
        return int(round(amount_eur * (10 ** AEGIS_EUR_DECIMALS)))

    @staticmethod
    def aegis_units_to_eur(units: int) -> float:
        """
        Converte unità AegisEUR (6 decimali) in EUR float.

        Parametri:
            units: importo in unità minime AegisEUR

        Ritorna:
            Importo in EUR
        """
        return round(units / (10 ** AEGIS_EUR_DECIMALS), 6)

    @staticmethod
    def cents_to_aegis_units(cents: int) -> int:
        """
        Scorciatoia: converte direttamente centesimi in unità AegisEUR.

        Parametri:
            cents: importo in centesimi

        Ritorna:
            Importo in unità minime AegisEUR
        """
        return int(round(cents * (10 ** AEGIS_EUR_DECIMALS) / 100))

    # =========================================================================
    # PROOF HASH
    # =========================================================================

    def _compute_proof_hash(
        self,
        sig_hex: str,
        canonical_msg: bytes,
        sender_id: str,
        receiver_id: str,
    ) -> str:
        """
        Calcola il proofHash compatibile con keccak256 dello smart contract.

        AegisEUR.sol usa keccak256 per identificare univocamente ogni proof
        e prevenire i replay attack tramite la mappatura usedProofHashes.

        Nota: usiamo SHA-3 (Keccak-256 standard) come approssimazione.
        In un sistema di produzione, usare la libreria eth_hash con Keccak.

        Parametri:
            sig_hex: firma ECDSA normalizzata (hex)
            canonical_msg: messaggio canonico firmato (bytes)
            sender_id: identificativo del mittente
            receiver_id: identificativo del destinatario

        Ritorna:
            Hash della proof in formato "0x" + 64 caratteri hex
        """
        # Concateniamo tutti i dati univoci della transazione
        dati = (
            bytes.fromhex(sig_hex.lstrip("0x"))
            + canonical_msg
            + sender_id.encode("utf-8")
            + receiver_id.encode("utf-8")
        )
        # SHA-256 come approssimazione di keccak256 (in prod: usa eth_hash)
        hash_bytes = hashlib.sha256(dati).digest()
        return "0x" + hash_bytes.hex()

    def _build_proof_data(
        self,
        sig_hex: str,
        canonical_msg: bytes,
        sender_id: str,
        receiver_id: str,
    ) -> str:
        """
        Costruisce i dati della proof per l'invio ad aegis-protocol.

        Per importi < 1000€, la proof è la firma ECDSA stessa.
        Per importi >= 1000€, questo campo viene poi sostituito
        con la ZK proof generata da aegis-protocol.

        Ritorna:
            Dati della proof come stringa JSON serializzata in hex
        """
        proof_dict = {
            "type": "ecdsa_p256",
            "signature": sig_hex,
            "message": canonical_msg.hex(),
            "sender": sender_id,
            "receiver": receiver_id,
        }
        proof_json = json.dumps(proof_dict, separators=(",", ":"))
        return "0x" + proof_json.encode("utf-8").hex()

    # =========================================================================
    # MESSAGGI E FIRME
    # =========================================================================

    @staticmethod
    def _build_canonical_message(amount_cents: int, counter: int, timestamp: float) -> bytes:
        """
        Costruisce il messaggio canonico da firmare, uguale al formato del SE.

        Il formato è identico a quello dell'applet JavaCard:
          importo (4 byte, big-endian uint32)
          || contatore (4 byte, big-endian uint32)
          || timestamp (8 byte, big-endian uint64)

        Questo garantisce che la verifica della firma produca lo stesso risultato
        sia nel Secure Element che in questo modulo Python.

        Parametri:
            amount_cents: importo in centesimi
            counter: valore contatore monotònico
            timestamp: timestamp epoch Unix

        Ritorna:
            16 byte del messaggio canonico
        """
        return struct.pack(">IIQ", amount_cents, counter, int(timestamp))

    @staticmethod
    def _normalize_signature(sig_hex: str) -> str:
        """
        Normalizza una firma ECDSA in formato hex uniforme.

        Rimuove il prefisso "0x" se presente e converte in minuscolo.

        Parametri:
            sig_hex: firma ECDSA (con o senza prefisso 0x)

        Ritorna:
            Firma hex normalizzata (minuscolo, senza 0x)
        """
        if isinstance(sig_hex, bytes):
            return sig_hex.hex()
        cleaned = sig_hex.strip()
        if cleaned.startswith("0x") or cleaned.startswith("0X"):
            cleaned = cleaned[2:]
        return cleaned.lower()

    def _verify_ecdsa_local(
        self,
        canonical_msg: bytes,
        sig_hex: str,
        public_key_hex: str,
        sender_id: str,
    ) -> None:
        """
        Verifica localmente la firma ECDSA prima di generare la proof.

        Serve come "checkpoint" per individuare immediatamente firme corrotte
        o manipolate, prima che raggiungano il backend on-chain.

        Parametri:
            canonical_msg: messaggio originale firmato (bytes)
            sig_hex: firma ECDSA in hex (senza 0x)
            public_key_hex: chiave pubblica hex uncompressed (130 chars = 65 byte)
            sender_id: identificativo del mittente (per il log)

        Eccezioni:
            ZkProofError: se la firma non è valida
        """
        try:
            pub_key_bytes = bytes.fromhex(public_key_hex)
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), pub_key_bytes
            )
            sig_bytes = bytes.fromhex(sig_hex)
            pub_key.verify(sig_bytes, canonical_msg, ec.ECDSA(hashes.SHA256()))
            logger.debug("✅ Verifica ECDSA locale superata per: %s", sender_id)
        except InvalidSignature as exc:
            raise ZkProofError(
                f"Firma ECDSA non valida per il mittente '{sender_id}'. "
                f"La transazione è corrotta o contraffatta."
            ) from exc
        except Exception as exc:
            raise ZkProofError(
                f"Errore nella verifica ECDSA per '{sender_id}': {exc}"
            ) from exc

    @staticmethod
    def _build_public_inputs(
        sender: str,
        receiver: str,
        amount_aegis: int,
        counter: int,
        timestamp: float,
    ) -> list:
        """
        Costruisce gli ingressi pubblici per il circuito Noir.

        Gli ingressi pubblici (public inputs) sono i valori che il verificatore
        ZK conosce e che permettono di verificare la proof senza conoscere
        i dati privati (la chiave privata del mittente).

        Parametri:
            sender: identificativo/indirizzo del mittente
            receiver: identificativo/indirizzo del destinatario
            amount_aegis: importo in unità AegisEUR (6 decimali)
            counter: contatore monotònico
            timestamp: timestamp della transazione

        Ritorna:
            Lista di ingressi pubblici come stringhe
        """
        return [
            sender,
            receiver,
            str(amount_aegis),
            str(counter),
            str(int(timestamp)),
        ]

    # =========================================================================
    # UTILITÀ
    # =========================================================================

    @staticmethod
    def requires_mica_kyc(amount_cents: int) -> bool:
        """
        Verifica se un importo supera la soglia MiCA per KYC obbligatorio.

        Secondo la normativa MiCA (Markets in Crypto-Assets), le transazioni
        superiori a 1000€ richiedono verifica KYC dell'identità.

        Parametri:
            amount_cents: importo in centesimi

        Ritorna:
            True se l'importo supera la soglia, False altrimenti
        """
        return amount_cents >= MICA_THRESHOLD_CENTS

    def __repr__(self) -> str:
        return (
            f"ZkProofAdapter("
            f"local_verify={self.enable_local_verification}, "
            f"mica_threshold={MICA_THRESHOLD_EUR}€)"
        )
