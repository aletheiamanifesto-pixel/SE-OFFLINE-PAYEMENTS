"""
identity_mapper.py — Mapping identità tra Secure Element e wallet on-chain

Gestisce l'associazione tra l'identità locale di un dispositivo Secure Element
(se_device_id) e il suo corrispondente wallet Ethereum on-chain.

Pensa a questo modulo come all'UFFICIO ANAGRAFE del sistema:
ogni carta NFC (Secure Element) ha un codice fiscale locale (se_device_id)
e una residenza digitale on-chain (wallet_address su Polygon Amoy).
Il registry mappa uno all'altro, con la chiave pubblica come documento d'identità.

La persistenza avviene su file JSON in config/, il che consente
di sopravvivere ai riavvii dell'applicazione senza database esterno.
"""

import json
import logging
import os
import re
import time
from typing import Optional

logger = logging.getLogger(__name__)

# =============================================================================
# COSTANTI
# =============================================================================

# Percorso di default del registry (relativo alla root del progetto)
DEFAULT_REGISTRY_PATH: str = os.path.join(
    os.path.dirname(__file__), "..", "config", "device_registry.json"
)

# Pattern per la validazione degli indirizzi Ethereum
# Un indirizzo Ethereum valido: "0x" + esattamente 40 caratteri hex
ETHEREUM_ADDRESS_PATTERN: re.Pattern = re.compile(r"^0x[0-9a-fA-F]{40}$")


class IdentityMapperError(Exception):
    """Eccezione base per errori dell'IdentityMapper."""


class DeviceNotFoundError(IdentityMapperError):
    """Sollevata quando il dispositivo non è nel registry."""


class InvalidAddressError(IdentityMapperError):
    """Sollevata quando l'indirizzo Ethereum non è valido."""


class IdentityMapper:
    """
    Registry locale che mappa se_device_id → wallet_address + public_key.

    Questa classe gestisce l'anagrafe dei dispositivi Secure Element registrati
    nel sistema. Ogni voce del registry contiene:
      - se_device_id: identificativo del chip NFC (es. "alice_wallet_roma_001")
      - wallet_address: indirizzo Ethereum on-chain (es. "0xAbc...123")
      - public_key: chiave pubblica ECDSA del SE (hex, 130 caratteri = 65 byte)
      - registered_at: timestamp di registrazione (epoch Unix)
      - metadata: dati opzionali aggiuntivi

    La persistenza è su file JSON, così il registry sopravvive ai riavvii.

    Attributi:
        registry_path: percorso del file JSON di persistenza
    """

    def __init__(self, registry_path: Optional[str] = None):
        """
        Inizializza l'IdentityMapper caricando il registry dal file JSON.

        Parametri:
            registry_path: percorso del file JSON di persistenza.
                           Se None, usa DEFAULT_REGISTRY_PATH.
        """
        self.registry_path: str = registry_path or DEFAULT_REGISTRY_PATH

        # Assicuriamoci che la directory esista
        os.makedirs(os.path.dirname(os.path.abspath(self.registry_path)), exist_ok=True)

        # Carica il registry dal file (o crea un registry vuoto)
        self._registry: dict[str, dict] = self._load()

        logger.info(
            "📋 IdentityMapper inizializzato: %d dispositivi registrati (%s)",
            len(self._registry),
            self.registry_path,
        )

    # =========================================================================
    # METODI PUBBLICI
    # =========================================================================

    def register_device(
        self,
        se_device_id: str,
        wallet_address: str,
        public_key: str,
        metadata: Optional[dict] = None,
        overwrite: bool = False,
    ) -> dict:
        """
        Registra un dispositivo Secure Element nel registry.

        Come iscrivere una nuova carta al servizio:
        associ il chip fisico (se_device_id) al tuo conto digitale (wallet_address).

        Parametri:
            se_device_id: identificativo univoco del dispositivo SE
                          (es. "alice_wallet_roma_001")
            wallet_address: indirizzo Ethereum del wallet on-chain
                            (deve essere nel formato 0x + 40 hex chars)
            public_key: chiave pubblica ECDSA del SE in formato hex uncompressed
                        (65 byte = 130 caratteri hex, inizia con "04")
            metadata: dizionario opzionale con dati aggiuntivi
            overwrite: se True, sovrascrive una registrazione esistente

        Ritorna:
            Voce del registry appena creata

        Eccezioni:
            InvalidAddressError: se wallet_address non è valido
            IdentityMapperError: se il dispositivo è già registrato (e overwrite=False)
        """
        # Validazione formato indirizzo Ethereum
        self._validate_address(wallet_address)

        # Controlla se il dispositivo è già registrato
        if se_device_id in self._registry and not overwrite:
            raise IdentityMapperError(
                f"Dispositivo '{se_device_id}' già registrato. "
                f"Usa overwrite=True per aggiornare."
            )

        voce: dict = {
            "se_device_id": se_device_id,
            "wallet_address": self._normalize_address(wallet_address),
            "public_key": public_key,
            "registered_at": time.time(),
            "metadata": metadata or {},
        }
        if se_device_id in self._registry:
            # Manteniamo la data di registrazione originale nell'aggiornamento
            voce["registered_at"] = self._registry[se_device_id].get(
                "registered_at", voce["registered_at"]
            )
            voce["updated_at"] = time.time()

        self._registry[se_device_id] = voce
        self._save()

        logger.info(
            "✅ Dispositivo registrato: %s → %s",
            se_device_id,
            voce["wallet_address"],
        )
        return voce

    def get_wallet_address(self, se_device_id: str) -> str:
        """
        Restituisce il wallet address on-chain associato al dispositivo SE.

        Come cercare l'indirizzo di casa di qualcuno nell'elenco telefonico.

        Parametri:
            se_device_id: identificativo del dispositivo SE

        Ritorna:
            Indirizzo Ethereum (0x + 40 hex chars)

        Eccezioni:
            DeviceNotFoundError: se il dispositivo non è nel registry
        """
        voce = self._get_entry(se_device_id)
        return voce["wallet_address"]

    def get_public_key(self, se_device_id: str) -> str:
        """
        Restituisce la chiave pubblica ECDSA del dispositivo SE.

        Come recuperare la firma depositata in banca per verificarla.

        Parametri:
            se_device_id: identificativo del dispositivo SE

        Ritorna:
            Chiave pubblica in formato hex (130 chars = 65 byte, punto non compresso)

        Eccezioni:
            DeviceNotFoundError: se il dispositivo non è nel registry
        """
        voce = self._get_entry(se_device_id)
        return voce["public_key"]

    def get_device_info(self, se_device_id: str) -> dict:
        """
        Restituisce tutte le informazioni di un dispositivo registrato.

        Parametri:
            se_device_id: identificativo del dispositivo SE

        Ritorna:
            Copia del dizionario con tutte le informazioni del dispositivo

        Eccezioni:
            DeviceNotFoundError: se il dispositivo non è nel registry
        """
        return dict(self._get_entry(se_device_id))

    def list_devices(self) -> list[dict]:
        """
        Elenca tutti i dispositivi SE registrati nel registry.

        Come sfogliare l'elenco completo delle carte attive.

        Ritorna:
            Lista di dizionari, uno per ogni dispositivo registrato
        """
        return [dict(v) for v in self._registry.values()]

    def is_registered(self, se_device_id: str) -> bool:
        """
        Verifica se un dispositivo è già registrato nel registry.

        Parametri:
            se_device_id: identificativo del dispositivo SE

        Ritorna:
            True se il dispositivo è registrato, False altrimenti
        """
        return se_device_id in self._registry

    def deregister_device(self, se_device_id: str) -> bool:
        """
        Rimuove un dispositivo dal registry.

        Come bloccare una carta smarrita: viene rimossa dall'anagrafe.

        Parametri:
            se_device_id: identificativo del dispositivo da rimuovere

        Ritorna:
            True se il dispositivo è stato rimosso, False se non era presente
        """
        if se_device_id not in self._registry:
            return False

        del self._registry[se_device_id]
        self._save()
        logger.info("🗑️  Dispositivo rimosso dal registry: %s", se_device_id)
        return True

    def find_by_wallet(self, wallet_address: str) -> Optional[dict]:
        """
        Cerca un dispositivo per indirizzo wallet (ricerca inversa).

        Come trovare il proprietario di una carta dato il numero di conto.

        Parametri:
            wallet_address: indirizzo Ethereum da cercare

        Ritorna:
            Dizionario del dispositivo se trovato, None altrimenti
        """
        normalized = self._normalize_address(wallet_address)
        for voce in self._registry.values():
            if voce["wallet_address"] == normalized:
                return dict(voce)
        return None

    def count(self) -> int:
        """Restituisce il numero di dispositivi registrati."""
        return len(self._registry)

    # =========================================================================
    # PERSISTENZA
    # =========================================================================

    def _load(self) -> dict:
        """
        Carica il registry dal file JSON.

        Se il file non esiste, restituisce un registry vuoto.
        """
        if not os.path.exists(self.registry_path):
            logger.debug("📋 File registry non trovato, creazione nuovo registry vuoto")
            return {}
        try:
            with open(self.registry_path, "r", encoding="utf-8") as f:
                dati = json.load(f)
            # Il registry è un dict {se_device_id: voce}
            if isinstance(dati, dict) and "devices" in dati:
                # Supporto formato legacy con wrapper "devices"
                return dati["devices"]
            return dati if isinstance(dati, dict) else {}
        except (json.JSONDecodeError, IOError) as exc:
            logger.error("❌ Errore caricamento registry da %s: %s", self.registry_path, exc)
            return {}

    def _save(self) -> None:
        """
        Salva il registry corrente sul file JSON.

        Usa la scrittura atomica (file temporaneo + rename) per evitare
        corruzioni in caso di interruzione durante il salvataggio.
        """
        try:
            tmp_path = self.registry_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self._registry, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self.registry_path)
            logger.debug("💾 Registry salvato: %d dispositivi", len(self._registry))
        except (IOError, OSError) as exc:
            logger.error("❌ Errore salvataggio registry: %s", exc)
            raise IdentityMapperError(f"Impossibile salvare il registry: {exc}") from exc

    # =========================================================================
    # METODI PRIVATI
    # =========================================================================

    def _get_entry(self, se_device_id: str) -> dict:
        """
        Recupera una voce dal registry o solleva DeviceNotFoundError.

        Parametri:
            se_device_id: identificativo del dispositivo

        Eccezioni:
            DeviceNotFoundError: se il dispositivo non è nel registry
        """
        if se_device_id not in self._registry:
            raise DeviceNotFoundError(
                f"Dispositivo '{se_device_id}' non trovato nel registry. "
                f"Registra prima il dispositivo con register_device()."
            )
        return self._registry[se_device_id]

    @staticmethod
    def _validate_address(address: str) -> None:
        """
        Valida il formato di un indirizzo Ethereum.

        Un indirizzo valido è "0x" seguito da esattamente 40 caratteri esadecimali.

        Parametri:
            address: stringa da validare

        Eccezioni:
            InvalidAddressError: se il formato non è valido
        """
        if not isinstance(address, str):
            raise InvalidAddressError(f"L'indirizzo deve essere una stringa, non {type(address)}")
        if not ETHEREUM_ADDRESS_PATTERN.match(address):
            raise InvalidAddressError(
                f"Indirizzo Ethereum non valido: '{address}'. "
                f"Formato atteso: 0x + 40 caratteri esadecimali"
            )

    @staticmethod
    def _normalize_address(address: str) -> str:
        """
        Normalizza un indirizzo Ethereum in minuscolo (eccetto il prefisso 0x).

        Converte in EIP-55 lowercase per confronti consistenti.
        """
        if address.startswith("0x") or address.startswith("0X"):
            return "0x" + address[2:].lower()
        return address.lower()

    def __repr__(self) -> str:
        return f"IdentityMapper(path={self.registry_path!r}, devices={len(self._registry)})"
