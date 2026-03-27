"""
AEGIS Offline Payments — Online Synchronization
=================================================

When a device regains internet connectivity, this module submits
locally stored transaction receipts to the AEGIS ledger for
permanent settlement.

The sync protocol:
    1. Collect all un-synced receipts from local storage
    2. Submit each receipt to the AEGIS settlement API
    3. Mark successfully settled receipts as synced
    4. Handle conflicts (double-spend attempts detected by the ledger)
"""

from __future__ import annotations

import json
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from .transaction import TransactionReceipt
from .exceptions import SyncError


@dataclass
class SyncResult:
    """Result of a synchronization attempt."""

    total: int = 0
    settled: int = 0
    failed: int = 0
    conflicts: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.failed == 0 and len(self.conflicts) == 0


class ReceiptStore:
    """
    Local receipt storage for offline operation.

    In production this would be backed by encrypted SQLite or
    platform-specific secure storage.  This reference implementation
    uses an in-memory dict.
    """

    def __init__(self):
        self._receipts: dict[str, dict] = {}  # hash → {receipt, synced}

    def store(self, receipt: TransactionReceipt) -> None:
        """Store a new receipt."""
        self._receipts[receipt.receipt_hash] = {
            "receipt": receipt,
            "synced": False,
            "stored_at": time.time(),
        }

    def get_unsynced(self) -> list[TransactionReceipt]:
        """Return all receipts not yet synchronized."""
        return [
            entry["receipt"]
            for entry in self._receipts.values()
            if not entry["synced"]
        ]

    def mark_synced(self, receipt_hash: str) -> None:
        """Mark a receipt as successfully settled."""
        if receipt_hash in self._receipts:
            self._receipts[receipt_hash]["synced"] = True

    def get_all(self) -> list[TransactionReceipt]:
        """Return all stored receipts."""
        return [entry["receipt"] for entry in self._receipts.values()]

    @property
    def count(self) -> int:
        return len(self._receipts)

    @property
    def unsynced_count(self) -> int:
        return sum(1 for e in self._receipts.values() if not e["synced"])


class SyncManager:
    """
    Handles online reconciliation of offline transactions.

    Parameters
    ----------
    api_url : str
        Base URL of the AEGIS settlement API.
    store : ReceiptStore
        Local receipt storage.
    """

    def __init__(self, api_url: str, store: ReceiptStore):
        self.api_url = api_url.rstrip("/")
        self.store = store

    def sync(self) -> SyncResult:
        """
        Attempt to synchronize all un-synced receipts.

        Returns
        -------
        SyncResult
            Summary of the sync operation.
        """
        unsynced = self.store.get_unsynced()
        result = SyncResult(total=len(unsynced))

        for receipt in unsynced:
            try:
                self._submit_receipt(receipt)
                self.store.mark_synced(receipt.receipt_hash)
                result.settled += 1
            except SyncError as e:
                if "conflict" in str(e).lower():
                    result.conflicts.append(receipt.receipt_hash)
                else:
                    result.failed += 1

        return result

    def _submit_receipt(self, receipt: TransactionReceipt) -> None:
        """
        Submit a single receipt to the AEGIS settlement API.

        In production this would make an HTTP POST request.
        This reference implementation simulates the API call.
        """
        # Build the settlement payload
        payload = {
            "version": receipt.version,
            "sender": receipt.sender_pubkey.hex(),
            "receiver": receipt.receiver_pubkey.hex(),
            "amount_cents": receipt.amount_cents,
            "counter": receipt.counter,
            "timestamp_ms": receipt.timestamp_ms,
            "signature": receipt.signature.hex(),
            "receipt_hash": receipt.receipt_hash,
        }

        # In production:
        # response = requests.post(f"{self.api_url}/settle", json=payload)
        # if response.status_code == 409:
        #     raise SyncError(f"Conflict: receipt {receipt.receipt_hash}")
        # response.raise_for_status()

        # Simulated: always succeeds
        _ = json.dumps(payload)  # Validate serialization
