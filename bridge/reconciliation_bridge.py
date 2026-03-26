#!/usr/bin/env python3
"""
reconciliation_bridge.py — Ponte di riconciliazione verso aegis-protocol

Quando la connessione internet è disponibile, questo bridge:
  1. Raccoglie le transazioni offline dai chip (via log locale)
  2. Le valida (firme ECDSA, contatori, saldi)
  3. Le invia alla blockchain AEGIS Protocol per la registrazione definitiva
  4. Riceve la conferma dalla blockchain
  5. Aggiorna lo stato locale

Uso:
    python reconciliation_bridge.py --submit tx_log.json
    python reconciliation_bridge.py --daemon  # avvia in modalità continua

Come libreria:
    from reconciliation_bridge import ReconciliationBridge
    bridge = ReconciliationBridge(aegis_endpoint="https://api.aegis-protocol.io")
    result = bridge.reconcile(transactions)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request

# Importa il simulatore per la verifica crittografica
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host-app", "python"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host-app/python"))

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)


# ─── Strutture dati ───────────────────────────────────────────────────────────

@dataclass
class OfflineTransaction:
    """
    Rappresenta una transazione eseguita offline.
    Corrisponde a un record nel log del chip SE.
    """

    tx_id:           str    # hash SHA-256 del payload
    timestamp:       float  # unix timestamp
    amount_cents:    int    # importo in centesimi
    sender_pubkey:   str    # chiave pubblica del pagante (hex)
    receiver_pubkey: str    # chiave pubblica del ricevente (hex)
    sender_counter:  int    # contatore del pagante al momento del pagamento
    signature:       str    # firma ECDSA (hex, DER format)
    payload_hex:     str    # payload originale firmato (hex)

    @classmethod
    def from_dict(cls, data: dict) -> "OfflineTransaction":
        return cls(**data)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def amount_euro(self) -> float:
        return self.amount_cents / 100

    def compute_tx_id(self) -> str:
        """Calcola l'ID della transazione come hash SHA-256 del payload."""
        return hashlib.sha256(bytes.fromhex(self.payload_hex)).hexdigest()

    def verify_id(self) -> bool:
        """Verifica che tx_id corrisponda al payload."""
        return self.tx_id == self.compute_tx_id()


@dataclass
class ReconciliationResult:
    """Risultato di una sessione di riconciliazione."""

    total_transactions:  int = 0
    accepted:            int = 0
    rejected:            int = 0
    pending:             int = 0
    errors:              list[str] = field(default_factory=list)
    accepted_tx_ids:     list[str] = field(default_factory=list)
    rejected_tx_ids:     list[str] = field(default_factory=list)
    blockchain_batch_id: Optional[str] = None
    timestamp:           float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        if self.total_transactions == 0:
            return 0.0
        return self.accepted / self.total_transactions

    def print_summary(self) -> None:
        print(f"\n📊 Riconciliazione completata:")
        print(f"   Totale transazioni: {self.total_transactions}")
        print(f"   ✅ Accettate:       {self.accepted}")
        print(f"   ❌ Rifiutate:       {self.rejected}")
        print(f"   ⏳ In sospeso:      {self.pending}")
        if self.blockchain_batch_id:
            print(f"   📬 Batch ID:        {self.blockchain_batch_id}")
        if self.errors:
            print(f"   ⚠️  Errori:          {len(self.errors)}")
            for e in self.errors[:3]:
                print(f"      - {e}")


# ─── Validatore locale ────────────────────────────────────────────────────────

class LocalValidator:
    """
    Valida le transazioni offline localmente prima di inviarle alla blockchain.
    Esegue controlli su firma ECDSA, contatori e integrità dei dati.
    """

    def __init__(self) -> None:
        self._seen_counters: dict[str, int] = {}  # pubkey_hex → last_counter

    def validate(self, tx: OfflineTransaction) -> tuple[bool, str]:
        """
        Valida una singola transazione.

        Returns:
            (is_valid, reason)
        """
        # 1. Verifica integrità tx_id
        if not tx.verify_id():
            return False, f"TX {tx.tx_id[:8]}...: tx_id non corrisponde al payload"

        # 2. Verifica importo
        if tx.amount_cents <= 0:
            return False, f"TX {tx.tx_id[:8]}...: importo non valido ({tx.amount_cents})"

        # 3. Verifica contatore anti-replay
        last_cnt = self._seen_counters.get(tx.sender_pubkey, -1)
        if tx.sender_counter <= last_cnt:
            return False, (
                f"TX {tx.tx_id[:8]}...: possibile replay "
                f"(contatore {tx.sender_counter} <= ultimo noto {last_cnt})"
            )

        # 4. Verifica firma ECDSA (se cryptography è disponibile)
        if CRYPTO_AVAILABLE:
            valid, err = self._verify_signature(tx)
            if not valid:
                return False, err

        # 5. Aggiorna il tracking dei contatori
        self._seen_counters[tx.sender_pubkey] = tx.sender_counter

        return True, "OK"

    def _verify_signature(self, tx: OfflineTransaction) -> tuple[bool, str]:
        """Verifica la firma ECDSA della transazione."""
        try:
            sender_pubkey_bytes = bytes.fromhex(tx.sender_pubkey)
            signature_bytes     = bytes.fromhex(tx.signature)
            payload_bytes       = bytes.fromhex(tx.payload_hex)

            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), sender_pubkey_bytes
            )
            pub_key.verify(signature_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
            return True, "OK"

        except InvalidSignature:
            return False, f"TX {tx.tx_id[:8]}...: firma ECDSA non valida"
        except Exception as e:
            return False, f"TX {tx.tx_id[:8]}...: errore verifica firma: {e}"


# ─── Bridge principale ────────────────────────────────────────────────────────

class ReconciliationBridge:
    """
    Bridge di riconciliazione verso la blockchain AEGIS Protocol.

    Raccoglie le transazioni offline, le valida localmente e le invia
    alla blockchain per la registrazione definitiva.
    """

    DEFAULT_ENDPOINT = "https://api.aegis-protocol.io/v1/reconcile"
    LOCAL_LOG_PATH   = Path("bridge_tx_log.json")

    def __init__(
        self,
        aegis_endpoint:  str = DEFAULT_ENDPOINT,
        local_log_path:  Path = LOCAL_LOG_PATH,
        timeout_seconds: int = 30,
        dry_run:         bool = False,
    ) -> None:
        """
        Args:
            aegis_endpoint:  URL dell'endpoint AEGIS per la riconciliazione.
            local_log_path:  Percorso del file di log locale delle transazioni.
            timeout_seconds: Timeout HTTP in secondi.
            dry_run:         Se True, non invia alla blockchain (solo validazione).
        """
        self.endpoint    = aegis_endpoint
        self.log_path    = local_log_path
        self.timeout     = timeout_seconds
        self.dry_run     = dry_run
        self.validator   = LocalValidator()

        logger.info("Bridge inizializzato (endpoint=%s, dry_run=%s)", aegis_endpoint, dry_run)

    def add_transaction(self, tx: OfflineTransaction) -> None:
        """Aggiunge una transazione al log locale (da sincronizzare poi)."""
        log = self._load_local_log()
        log.append(tx.to_dict())
        self._save_local_log(log)
        logger.debug("Transazione aggiunta al log locale: %s", tx.tx_id[:8])

    def add_transaction_from_simulator(
        self,
        amount_cents:    int,
        sender_pubkey:   bytes,
        receiver_pubkey: bytes,
        sender_counter:  int,
        signature:       bytes,
        payload:         bytes,
    ) -> OfflineTransaction:
        """
        Crea e aggiunge una transazione a partire dai dati del simulatore SE.

        Returns:
            La transazione creata.
        """
        payload_hex   = payload.hex()
        tx_id         = hashlib.sha256(payload).hexdigest()

        tx = OfflineTransaction(
            tx_id           = tx_id,
            timestamp       = time.time(),
            amount_cents    = amount_cents,
            sender_pubkey   = sender_pubkey.hex(),
            receiver_pubkey = receiver_pubkey.hex(),
            sender_counter  = sender_counter,
            signature       = signature.hex(),
            payload_hex     = payload_hex,
        )
        self.add_transaction(tx)
        return tx

    def reconcile(
        self, transactions: Optional[list[OfflineTransaction]] = None
    ) -> ReconciliationResult:
        """
        Esegue la riconciliazione delle transazioni offline.

        Args:
            transactions: Lista di transazioni da riconciliare.
                         Se None, usa il log locale.

        Returns:
            ReconciliationResult con i dettagli dell'operazione.
        """
        if transactions is None:
            transactions = self._load_transactions_from_log()

        result = ReconciliationResult(total_transactions=len(transactions))

        if not transactions:
            logger.info("Nessuna transazione da riconciliare.")
            return result

        logger.info("Avvio riconciliazione di %d transazioni...", len(transactions))

        # ── Fase 1: Validazione locale ─────────────────────────────────────
        valid_txs:   list[OfflineTransaction] = []
        invalid_txs: list[OfflineTransaction] = []

        for tx in transactions:
            is_valid, reason = self.validator.validate(tx)
            if is_valid:
                valid_txs.append(tx)
            else:
                invalid_txs.append(tx)
                result.errors.append(reason)
                result.rejected_tx_ids.append(tx.tx_id)
                logger.warning("Transazione rifiutata: %s", reason)

        result.rejected = len(invalid_txs)

        if not valid_txs:
            logger.info("Nessuna transazione valida da inviare.")
            return result

        # ── Fase 2: Invio alla blockchain ──────────────────────────────────
        if self.dry_run:
            logger.info("[DRY RUN] Non invio alla blockchain (dry_run=True)")
            result.accepted = len(valid_txs)
            result.accepted_tx_ids = [tx.tx_id for tx in valid_txs]
            result.blockchain_batch_id = "DRY-RUN-" + str(int(time.time()))
        else:
            batch_result = self._submit_to_blockchain(valid_txs)
            result.accepted          = batch_result.get("accepted", 0)
            result.rejected         += batch_result.get("rejected", 0)
            result.pending           = batch_result.get("pending", 0)
            result.accepted_tx_ids   = batch_result.get("accepted_ids", [])
            result.blockchain_batch_id = batch_result.get("batch_id")

            # Aggiungi eventuali errori dalla blockchain
            for err in batch_result.get("errors", []):
                result.errors.append(f"Blockchain: {err}")

        # ── Fase 3: Pulizia log locale ─────────────────────────────────────
        self._remove_reconciled_from_log(result.accepted_tx_ids)

        logger.info(
            "Riconciliazione completata: %d accettate, %d rifiutate",
            result.accepted, result.rejected
        )
        return result

    def _submit_to_blockchain(
        self, transactions: list[OfflineTransaction]
    ) -> dict[str, Any]:
        """
        Invia un batch di transazioni all'endpoint AEGIS.

        Returns:
            Risposta della blockchain (dict).
        """
        payload = {
            "protocol_version": "1.0",
            "batch_timestamp":  time.time(),
            "transactions":     [tx.to_dict() for tx in transactions],
        }
        payload_bytes = json.dumps(payload).encode("utf-8")

        req = urllib_request.Request(
            url    = self.endpoint,
            data   = payload_bytes,
            method = "POST",
            headers = {
                "Content-Type":  "application/json",
                "User-Agent":    "AEGIS-ReconciliationBridge/1.0",
                "X-Batch-Size":  str(len(transactions)),
            },
        )

        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))
                logger.info("Blockchain risposta: %s", response_data.get("status"))
                return response_data

        except urllib_error.HTTPError as e:
            logger.error("HTTP error: %s %s", e.code, e.reason)
            return {"accepted": 0, "rejected": len(transactions),
                    "errors": [f"HTTP {e.code}: {e.reason}"]}

        except urllib_error.URLError as e:
            logger.error("URL error (offline?): %s", e.reason)
            return {"accepted": 0, "rejected": 0, "pending": len(transactions),
                    "errors": [f"Connessione non disponibile: {e.reason}"]}

        except Exception as e:
            logger.error("Errore imprevisto: %s", e)
            return {"accepted": 0, "rejected": 0, "errors": [str(e)]}

    # ─── Gestione log locale ──────────────────────────────────────────────────

    def _load_local_log(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        with open(self.log_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_local_log(self, data: list[dict]) -> None:
        with open(self.log_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _load_transactions_from_log(self) -> list[OfflineTransaction]:
        raw = self._load_local_log()
        return [OfflineTransaction.from_dict(d) for d in raw]

    def _remove_reconciled_from_log(self, accepted_ids: list[str]) -> None:
        if not accepted_ids:
            return
        accepted_set = set(accepted_ids)
        log = self._load_local_log()
        remaining = [tx for tx in log if tx.get("tx_id") not in accepted_set]
        self._save_local_log(remaining)
        logger.debug("Rimosse %d transazioni reconciliate dal log locale",
                     len(log) - len(remaining))


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Bridge di riconciliazione AEGIS Protocol"
    )
    parser.add_argument("--endpoint",  default=ReconciliationBridge.DEFAULT_ENDPOINT,
                        help="Endpoint API AEGIS")
    parser.add_argument("--submit",    metavar="FILE",
                        help="File JSON con le transazioni da riconciliare")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Valida senza inviare alla blockchain")
    parser.add_argument("--daemon",    action="store_true",
                        help="Avvia in modalità daemon (reconcilia ogni 60s)")
    parser.add_argument("--interval",  type=int, default=60,
                        help="Intervallo in secondi (modalità daemon, default: 60)")

    args = parser.parse_args()

    bridge = ReconciliationBridge(
        aegis_endpoint = args.endpoint,
        dry_run        = args.dry_run,
    )

    if args.submit:
        # Riconcilia da file
        with open(args.submit, "r", encoding="utf-8") as f:
            raw = json.load(f)
        transactions = [OfflineTransaction.from_dict(tx) for tx in raw]
        result = bridge.reconcile(transactions)
        result.print_summary()

    elif args.daemon:
        # Modalità daemon
        print(f"🔄 Bridge avviato in modalità daemon (intervallo: {args.interval}s)")
        print("   Premi Ctrl+C per uscire.\n")
        while True:
            try:
                result = bridge.reconcile()
                if result.total_transactions > 0:
                    result.print_summary()
                else:
                    print(f"  [{time.strftime('%H:%M:%S')}] Nessuna transazione pendente.")
                time.sleep(args.interval)
            except KeyboardInterrupt:
                print("\n👋 Bridge fermato.")
                break

    else:
        # Riconcilia dal log locale
        result = bridge.reconcile()
        result.print_summary()


if __name__ == "__main__":
    main()
