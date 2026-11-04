"""
bridge — Pacchetto di riconciliazione SE-OFFLINE-PAYEMENTS ↔ aegis-protocol

Esporta le classi principali del bridge per l'integrazione tra il sistema
di pagamenti offline su Secure Element e il backend blockchain aegis-protocol.

Utilizzo tipico:
    from bridge import AegisReconciler, AegisClient, IdentityMapper, ZkProofAdapter

    client = AegisClient(base_url="http://localhost:8000")
    mapper = IdentityMapper()
    reconciler = AegisReconciler(aegis_client=client, identity_mapper=mapper)
    reconciler.add_transaction(tx_data)
    risultato = reconciler.reconcile()
"""

from .reconciliation_bridge import ReconciliationBridge, TransactionData
from .aegis_client import AegisClient, AegisApiError
from .aegis_reconciler import AegisReconciler, ReconciliationResult
from .identity_mapper import IdentityMapper, DeviceNotFoundError, InvalidAddressError
from .zk_proof_adapter import ZkProofAdapter, ZkProofError
from .emittente import Emittente, OperazioneRifiutata, RapportoSincronizzazione

__all__ = [
    # Emittente del protocollo v2 (carica, scarica, riconcilia, revoche)
    "Emittente",
    "OperazioneRifiutata",
    "RapportoSincronizzazione",
    # Bridge base (non modificato)
    "ReconciliationBridge",
    "TransactionData",
    # Client HTTP per aegis-protocol
    "AegisClient",
    "AegisApiError",
    # Riconciliatore reale
    "AegisReconciler",
    "ReconciliationResult",
    # Registry identità SE ↔ wallet
    "IdentityMapper",
    "DeviceNotFoundError",
    "InvalidAddressError",
    # Adattatore ZK proof
    "ZkProofAdapter",
    "ZkProofError",
]
