"""
reconciliation_bridge.py — Ponte di Riconciliazione tra Offline e Blockchain

Immagina di essere un commerciante ambulante che lavora tutto il giorno al mercato
senza internet. Ogni vendita viene registrata su un quaderno (le transazioni offline).
A sera, quando torni a casa e hai il Wi-Fi, trascrivi tutto nel libro mastro
digitale (la blockchain AEGIS). Questo modulo è quel "ponte" tra il quaderno
e il libro mastro.

Il ReconciliationBridge:
1. RACCOGLIE le transazioni offline durante la giornata (come appuntarle sul quaderno)
2. Le VERIFICA una per una (come controllare che i conti tornino)
3. Le RICONCILIA con il protocollo AEGIS on-chain (come trascrivere nel libro mastro)
4. Può ESPORTARE un batch per elaborazione asincrona (come mandare il quaderno al commercialista)

In un sistema reale, il bridge comunicherebbe con uno smart contract sulla blockchain.
In questa simulazione, logghiamo le operazioni per dimostrare il flusso.
"""

import json
import time
from typing import Optional


class TransactionData:
    """
    Struttura dati per una transazione offline.

    Ogni transazione è come uno SCONTRINO FISCALE digitale:
    ha un mittente, un destinatario, un importo, un numero progressivo (contatore),
    una firma e un timbro temporale.

    Campi:
        sender_id: identificativo del pagatore (come il codice fiscale)
        receiver_id: identificativo del ricevente
        amount: importo in centesimi (es. 2500 = 25.00€)
        counter: valore del contatore monotònico al momento della transazione
        signature: firma ECDSA in formato esadecimale
        timestamp: momento della transazione (epoch Unix)
    """

    def __init__(self, sender_id: str, receiver_id: str, amount: int,
                 counter: int, signature: str, timestamp: Optional[float] = None):
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.amount = amount
        self.counter = counter
        self.signature = signature
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> dict:
        """
        Converte la transazione in un dizionario.
        Come fotocopiare lo scontrino per l'archivio.
        """
        return {
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "amount": self.amount,
            "counter": self.counter,
            "signature": self.signature,
            "timestamp": self.timestamp
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TransactionData":
        """
        Ricostruisce una transazione da un dizionario.
        Come rileggere lo scontrino dall'archivio.
        """
        return cls(
            sender_id=data["sender_id"],
            receiver_id=data["receiver_id"],
            amount=data["amount"],
            counter=data["counter"],
            signature=data["signature"],
            timestamp=data.get("timestamp", time.time())
        )

    def __repr__(self) -> str:
        return (f"TX[{self.sender_id} → {self.receiver_id}: "
                f"{self.amount / 100:.2f}€ | cnt={self.counter}]")


class ReconciliationBridge:
    """
    Ponte di riconciliazione tra transazioni offline e blockchain AEGIS.

    Questa classe funziona come un UFFICIO POSTALE per le transazioni:
    - Le transazioni arrivano (add_transaction) come lettere in una cassetta
    - Vengono verificate (verify_transaction) come controllare indirizzo e francobollo
    - Vengono smistaste e inviate (reconcile) come il postino che consegna
    - Possono essere raggruppate in un pacco (export_batch) per invio massivo

    Nel mondo reale, il metodo reconcile() chiamerebbe le API di uno smart contract
    sulla blockchain AEGIS. In questa simulazione, logghiamo le operazioni.
    """

    def __init__(self):
        """
        Inizializza il bridge.

        Come aprire un nuovo ufficio postale:
        - La cassetta delle lettere è vuota (nessuna transazione pendente)
        - Il registro delle consegne è pulito (nessuna transazione riconciliata)
        - Il log degli eventi è pronto
        """
        # Coda delle transazioni pendenti — la "cassetta delle lettere"
        self._pending_transactions: list[TransactionData] = []

        # Archivio delle transazioni riconciliate — il "registro delle consegne"
        self._reconciled_transactions: list[TransactionData] = []

        # Log degli eventi — il "diario dell'ufficio postale"
        self._event_log: list[str] = []

    def add_transaction(self, tx_data: dict) -> bool:
        """
        Aggiunge una transazione alla coda di riconciliazione.

        Come imbucare una lettera nella cassetta postale:
        la lettera viene accettata solo se ha tutti i campi obbligatori.

        Parametri:
            tx_data: dizionario con i campi della transazione
                     (sender_id, receiver_id, amount, counter, signature)

        Ritorna:
            True se la transazione è stata accettata, False altrimenti
        """
        # Verifica che tutti i campi obbligatori siano presenti
        # Come controllare che la busta abbia indirizzo, mittente e francobollo
        campi_obbligatori = ["sender_id", "receiver_id", "amount", "counter", "signature"]
        for campo in campi_obbligatori:
            if campo not in tx_data:
                self._log(f"❌ Transazione rifiutata: campo '{campo}' mancante")
                return False

        # Aggiungiamo il timestamp se non presente
        if "timestamp" not in tx_data:
            tx_data["timestamp"] = time.time()

        transazione = TransactionData.from_dict(tx_data)
        self._pending_transactions.append(transazione)
        self._log(f"📬 Transazione aggiunta: {transazione}")
        return True

    def get_pending_transactions(self) -> list[dict]:
        """
        Restituisce tutte le transazioni in attesa di riconciliazione.

        Come aprire la cassetta delle lettere e guardare quante ce ne sono.

        Ritorna:
            Lista di dizionari, uno per ogni transazione pendente
        """
        return [tx.to_dict() for tx in self._pending_transactions]

    def verify_transaction(self, tx_data: dict) -> bool:
        """
        Verifica la validità formale di una transazione.

        Questo è un controllo di INTEGRITÀ, come quando il postino
        verifica che la lettera abbia l'indirizzo completo e il
        francobollo giusto prima di consegnarla.

        Controlli effettuati:
        1. Tutti i campi obbligatori sono presenti
        2. L'importo è positivo (non puoi spedire una lettera vuota)
        3. Il contatore è non-negativo
        4. La firma non è vuota

        In un sistema reale, qui si verificherebbe anche la firma ECDSA
        contro la chiave pubblica del mittente, consultando un registro
        di chiavi pubbliche (PKI - Public Key Infrastructure).

        Parametri:
            tx_data: dizionario con i dati della transazione

        Ritorna:
            True se la transazione supera tutti i controlli, False altrimenti
        """
        # Controllo 1: Campi obbligatori presenti
        campi_obbligatori = ["sender_id", "receiver_id", "amount", "counter", "signature"]
        for campo in campi_obbligatori:
            if campo not in tx_data:
                self._log(f"⚠️ Verifica fallita: campo '{campo}' mancante")
                return False

        # Controllo 2: Importo positivo
        # Non ha senso trasferire 0€ o importi negativi
        if tx_data["amount"] <= 0:
            self._log(f"⚠️ Verifica fallita: importo non valido ({tx_data['amount']})")
            return False

        # Controllo 3: Contatore non-negativo
        # Il contatore monotònico parte da 0 e sale, non può essere negativo
        if tx_data["counter"] < 0:
            self._log(f"⚠️ Verifica fallita: contatore negativo ({tx_data['counter']})")
            return False

        # Controllo 4: Firma non vuota
        # Una transazione senza firma è come un assegno senza firma: non vale
        if not tx_data["signature"]:
            self._log("⚠️ Verifica fallita: firma mancante")
            return False

        self._log(f"✅ Transazione verificata: {tx_data['sender_id']} → {tx_data['receiver_id']}")
        return True

    def reconcile(self, api_url: str = "https://aegis.protocol/api/v1/reconcile") -> dict:
        """
        Riconcilia le transazioni pendenti con il protocollo AEGIS on-chain.

        Questa è la fase cruciale: come quando il commerciante a fine giornata
        va in banca a depositare l'incasso. Ogni transazione offline viene
        registrata sulla blockchain, rendendola permanente e verificabile.

        In questa simulazione, NON facciamo chiamate HTTP reali.
        Logghiamo ogni passaggio per dimostrare il flusso.

        Parametri:
            api_url: URL dell'endpoint di riconciliazione (simulato)

        Ritorna:
            Dizionario con il risultato: successi, fallimenti, totale
        """
        risultato = {
            "totale": len(self._pending_transactions),
            "successi": 0,
            "fallimenti": 0,
            "url": api_url,
            "timestamp": time.time()
        }

        self._log(f"\n🔄 Inizio riconciliazione di {risultato['totale']} transazioni...")
        self._log(f"   Endpoint: {api_url}")

        # Processiamo ogni transazione pendente
        # Come il cassiere che conta e registra ogni scontrino della giornata
        transazioni_da_rimuovere = []

        for i, tx in enumerate(self._pending_transactions):
            tx_dict = tx.to_dict()

            # Verifichiamo la transazione prima di riconciliarla
            if self.verify_transaction(tx_dict):
                # Simulazione della chiamata API
                # In un sistema reale qui ci sarebbe: requests.post(api_url, json=tx_dict)
                self._log(f"   📤 [{i + 1}/{risultato['totale']}] "
                          f"Invio: {tx} → blockchain AEGIS")
                self._log(f"   📥 Risposta simulata: 200 OK — transazione registrata on-chain")

                self._reconciled_transactions.append(tx)
                transazioni_da_rimuovere.append(tx)
                risultato["successi"] += 1
            else:
                self._log(f"   ❌ [{i + 1}/{risultato['totale']}] "
                          f"Transazione {tx} non superata la verifica")
                risultato["fallimenti"] += 1

        # Rimuoviamo le transazioni riconciliate dalla coda pendente
        for tx in transazioni_da_rimuovere:
            self._pending_transactions.remove(tx)

        self._log(f"🏁 Riconciliazione completata: "
                  f"{risultato['successi']} OK, {risultato['fallimenti']} errori\n")

        return risultato

    def export_batch(self, filename: str) -> bool:
        """
        Esporta le transazioni pendenti in un file JSON per elaborazione batch.

        Come preparare un pacco di scontrini da mandare al commercialista:
        li mettiamo tutti in una busta (file JSON) ordinati e leggibili.

        Parametri:
            filename: percorso del file di output (es. "batch_2024.json")

        Ritorna:
            True se l'esportazione è riuscita, False altrimenti
        """
        try:
            batch = {
                "versione": "1.0",
                "timestamp_export": time.time(),
                "numero_transazioni": len(self._pending_transactions),
                "transazioni": [tx.to_dict() for tx in self._pending_transactions]
            }

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(batch, f, indent=2, ensure_ascii=False)

            self._log(f"📦 Batch esportato: {len(self._pending_transactions)} "
                      f"transazioni → {filename}")
            return True

        except (IOError, OSError) as e:
            self._log(f"❌ Errore esportazione batch: {e}")
            return False

    def get_event_log(self) -> list[str]:
        """
        Restituisce il log degli eventi del bridge.
        Come leggere il diario dell'ufficio postale.
        """
        return self._event_log.copy()

    def _log(self, messaggio: str):
        """
        Registra un evento nel log interno.
        Come annotare un'operazione nel registro dell'ufficio.
        """
        entry = f"[{time.strftime('%H:%M:%S')}] {messaggio}"
        self._event_log.append(entry)
        print(entry)
