"""
resilient_payment.py — Flusso di pagamento resiliente con retry e rollback automatico

Questo modulo estende il flusso di pagamento base aggiungendo:
  1. ROLLBACK automatico: se il credit fallisce dopo un debit riuscito,
     si restituisce l'importo al pagatore (pagamento annullato)
  2. RETRY configurabile: in caso di errori NFC transienti (timeout,
     interferenze), il sistema riprova automaticamente
  3. LOGGING delle torn transaction: ogni transazione parziale viene
     registrata per la riconciliazione futura
  4. COMPATIBILITÀ universale: accetta qualsiasi SecureElementInterface,
     sia simulatore che hardware reale

CONCETTO DI TORN TRANSACTION:
  Una "torn transaction" è una transazione strappata a metà — il pagatore
  ha eseguito il debit ma il credit al ricevente non è completato.
  È come strappare un assegno a metà durante il trasferimento.

  Per gestirla correttamente, si può:
  a) Fare rollback (se il pagatore è ancora raggiungibile)
  b) Loggare e riconciliare offline (se il rollback non è possibile)
"""

import logging
import struct
import time
from typing import Optional

from .se_interface import SecureElementInterface
from .hardware_errors import (
    HardwareError, NFCTimeoutError, TornTransactionError, CardCommunicationError
)

# Logger per diagnostica e audit trail
logger = logging.getLogger(__name__)

# Numero di tentativi di default per operazioni che possono avere errori transienti
DEFAULT_MAX_RETRIES = 3

# Pausa tra i tentativi (secondi) — cresce con ogni tentativo (backoff esponenziale)
DEFAULT_RETRY_DELAY_SEC = 0.2


class ResilientPaymentFlow:
    """
    Flusso di pagamento robusto per ambienti hardware reali.

    A differenza del flusso base (payment_flow.py), questa classe:
    - Gestisce gli errori hardware transienti con retry automatico
    - Esegue rollback se il credit fallisce dopo un debit riuscito
    - Logga le torn transaction per la riconciliazione offline
    - Funziona con qualsiasi implementazione di SecureElementInterface

    UTILIZZO:
        from host_app.python.se_factory import create_secure_element

        pagatore = create_secure_element("simulator", initial_balance=10000)
        ricevente = create_secure_element("simulator", initial_balance=5000)

        flusso = ResilientPaymentFlow(max_retries=3)
        successo = flusso.esegui_pagamento(pagatore, ricevente, importo=2500)
    """

    def __init__(
        self,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_delay_sec: float = DEFAULT_RETRY_DELAY_SEC
    ):
        """
        Inizializza il flusso di pagamento resiliente.

        Parametri:
            max_retries: numero massimo di tentativi per errori transienti
            retry_delay_sec: pausa base tra i tentativi (si moltiplica per il numero del tentativo)
        """
        if max_retries < 1:
            raise ValueError(f"max_retries deve essere >= 1, ricevuto: {max_retries}")
        self._max_retries = max_retries
        self._retry_delay_sec = retry_delay_sec

    def esegui_pagamento(
        self,
        pagatore: SecureElementInterface,
        ricevente: SecureElementInterface,
        importo: int
    ) -> bool:
        """
        Esegue un pagamento resiliente tra due Secure Element.

        Gestisce automaticamente:
        - Retry per errori NFC transienti
        - Rollback se il credit fallisce dopo un debit riuscito
        - Logging completo per audit e riconciliazione

        Parametri:
            pagatore: il SE di chi paga (qualsiasi SecureElementInterface)
            ricevente: il SE di chi riceve (qualsiasi SecureElementInterface)
            importo: l'importo in centesimi (es. 2500 = 25.00€)

        Ritorna:
            True se il pagamento è completato con successo, False altrimenti

        Eccezioni:
            TornTransactionError: se il debit è avvenuto ma il rollback è fallito
            ValueError: se l'importo non è valido
        """
        if importo <= 0:
            raise ValueError(f"Importo non valido: {importo}. Deve essere > 0.")

        importo_euro = importo / 100.0
        logger.info(f"Avvio pagamento resiliente: {importo_euro:.2f}€")

        # --- FASE 1: Verifica saldo preventiva ---
        try:
            saldo_pagatore = self._esegui_con_retry(pagatore.get_balance)
        except HardwareError as e:
            logger.error(f"Impossibile leggere il saldo del pagatore: {e}")
            return False

        if saldo_pagatore < importo:
            logger.warning(
                f"Saldo insufficiente: {saldo_pagatore / 100:.2f}€ disponibili, "
                f"{importo_euro:.2f}€ richiesti"
            )
            return False

        # --- FASE 2: Debit sul pagatore ---
        debit_riuscito = False
        try:
            debit_riuscito = self._esegui_con_retry(pagatore.debit, importo)
            if not debit_riuscito:
                logger.warning(f"Debit di {importo_euro:.2f}€ rifiutato (saldo insufficiente)")
                return False
            logger.info(f"Debit di {importo_euro:.2f}€ riuscito")
        except HardwareError as e:
            logger.error(f"Errore hardware durante il debit: {e}")
            return False

        # --- FASE 3: Credit al ricevente (con rollback se fallisce) ---
        try:
            credit_riuscito = self._esegui_con_retry(ricevente.credit, importo)
            if not credit_riuscito:
                logger.error("Credit al ricevente rifiutato — tentativo di rollback")
                self._esegui_rollback(pagatore, importo)
                return False
            logger.info(f"Credit di {importo_euro:.2f}€ riuscito")
        except NFCTimeoutError as e:
            # Stato incerto: il debit è avvenuto, il credit è dubbio
            logger.critical(
                f"TORN TRANSACTION: timeout durante il credit dopo un debit riuscito. "
                f"Importo: {importo_euro:.2f}€. Errore: {e}"
            )
            # Tenta il rollback — potrebbe non essere possibile se la carta non risponde
            rollback_riuscito = self._esegui_rollback(pagatore, importo)
            if not rollback_riuscito:
                raise TornTransactionError(
                    f"Transazione interrotta: debit eseguito ma credit fallito. "
                    f"Importo: {importo_euro:.2f}€. Rollback fallito.",
                    amount=importo,
                    payer_debited=True,
                    receiver_credited=False
                )
            return False
        except HardwareError as e:
            logger.error(f"Errore hardware durante il credit: {e} — tentativo di rollback")
            self._esegui_rollback(pagatore, importo)
            return False

        logger.info(
            f"Pagamento completato: {importo_euro:.2f}€ da pagatore a ricevente. "
            f"Saldo pagatore: {pagatore.get_balance() / 100:.2f}€, "
            f"Saldo ricevente: {ricevente.get_balance() / 100:.2f}€"
        )
        return True

    def _esegui_rollback(self, pagatore: SecureElementInterface, importo: int) -> bool:
        """
        Tenta di annullare un debit restituendo l'importo al pagatore.

        In caso di rollback riuscito, il pagatore viene riaccreditato
        dell'importo addebitato, ripristinando il saldo originale.

        Parametri:
            pagatore: il SE del pagatore a cui restituire i fondi
            importo: l'importo da restituire in centesimi

        Ritorna:
            True se il rollback è riuscito, False altrimenti
        """
        importo_euro = importo / 100.0
        logger.warning(f"Tentativo di rollback: restituzione di {importo_euro:.2f}€ al pagatore")

        try:
            riuscito = self._esegui_con_retry(pagatore.credit, importo)
            if riuscito:
                logger.info(f"Rollback riuscito: {importo_euro:.2f}€ restituiti al pagatore")
            else:
                logger.error(f"Rollback fallito: credit di {importo_euro:.2f}€ rifiutato")
            return riuscito
        except HardwareError as e:
            logger.critical(
                f"ROLLBACK FALLITO: impossibile restituire {importo_euro:.2f}€ al pagatore. "
                f"Errore: {e}. Intervento manuale necessario."
            )
            return False

    def _esegui_con_retry(self, funzione, *args, **kwargs):
        """
        Esegue una funzione con retry automatico per errori transienti.

        Riprova automaticamente in caso di NFCTimeoutError o CardCommunicationError.
        Non riprova in caso di errori logici (es. saldo insufficiente).

        Parametri:
            funzione: il callable da eseguire
            *args: argomenti posizionali da passare alla funzione
            **kwargs: argomenti keyword da passare alla funzione

        Ritorna:
            Il valore di ritorno della funzione

        Eccezioni:
            L'ultima eccezione se tutti i tentativi falliscono
        """
        ultimo_errore = None

        for tentativo in range(1, self._max_retries + 1):
            try:
                return funzione(*args, **kwargs)
            except (NFCTimeoutError, CardCommunicationError) as e:
                ultimo_errore = e
                if tentativo < self._max_retries:
                    pausa = self._retry_delay_sec * tentativo
                    logger.warning(
                        f"Errore transitorio (tentativo {tentativo}/{self._max_retries}): {e}. "
                        f"Riprovo tra {pausa:.1f}s..."
                    )
                    time.sleep(pausa)
                else:
                    logger.error(
                        f"Tutti i tentativi esauriti ({self._max_retries}). "
                        f"Ultimo errore: {e}"
                    )
            except HardwareError:
                # Errori non transienti (es. card not found): rilancia subito
                raise

        raise ultimo_errore
