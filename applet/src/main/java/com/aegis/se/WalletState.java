package com.aegis.se;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Stato del portafoglio memorizzato nel chip Secure Element.
 *
 * Contiene:
 *  - Saldo corrente in centesimi di euro (uint64, big-endian)
 *  - Contatore monotonico anti-frode
 *  - Accumulatore spesa offline (per limiti)
 *  - Log degli ultimi {@link APDUConstants#MAX_TX_LOG_SIZE} pagamenti
 *
 * Tutti i dati sono in memoria persistente (EEPROM) tranne i buffer
 * temporanei di elaborazione.
 */
public class WalletState {

    // ─── Saldo ────────────────────────────────────────────────────────────────

    /**
     * Saldo in centesimi di euro, formato uint64 big-endian (8 byte).
     * Es. 10000 = 100.00€
     */
    private final byte[] balance;

    /**
     * Totale speso offline dall'ultima riconciliazione (centesimi, 8 byte).
     * Usato per il controllo del limite OFFLINE_SPEND_LIMIT_CENTS.
     */
    private final byte[] offlineSpent;

    // ─── Contatore ────────────────────────────────────────────────────────────

    /** Contatore monotonico anti-replay. */
    private final MonotonicCounter counter;

    // ─── Log transazioni ──────────────────────────────────────────────────────

    /**
     * Log circolare delle ultime MAX_TX_LOG_SIZE transazioni.
     * Ogni record: 8B importo + 4B contatore + 65B chiave pubblica controparte.
     */
    private static final short TX_RECORD_SIZE =
            APDUConstants.SIZE_BALANCE + APDUConstants.SIZE_COUNTER + APDUConstants.SIZE_PUBLIC_KEY; // 77

    private final byte[] txLog;
    private short txLogHead;  // indice del prossimo slot da scrivere
    private short txLogCount; // numero di transazioni registrate

    // ─── Costruttore ──────────────────────────────────────────────────────────

    /**
     * Crea un nuovo portafoglio con saldo zero.
     */
    public WalletState() {
        balance      = new byte[APDUConstants.SIZE_BALANCE];
        offlineSpent = new byte[APDUConstants.SIZE_BALANCE];
        counter      = new MonotonicCounter();

        txLog     = new byte[(short) (TX_RECORD_SIZE * APDUConstants.MAX_TX_LOG_SIZE)];
        txLogHead  = 0;
        txLogCount = 0;
    }

    // ─── Saldo ────────────────────────────────────────────────────────────────

    /**
     * Restituisce il saldo corrente in centesimi.
     *
     * @return saldo (0 … Long.MAX_VALUE)
     */
    public long getBalance() {
        return bytesToLong(balance, (short) 0);
    }

    /**
     * Copia il saldo nel buffer fornito (8 byte big-endian).
     *
     * @param dest   buffer di destinazione
     * @param offset offset
     */
    public void copyBalanceTo(byte[] dest, short offset) {
        Util.arrayCopy(balance, (short) 0, dest, offset, APDUConstants.SIZE_BALANCE);
    }

    /**
     * Imposta il saldo. Usato solo al caricamento iniziale / riconciliazione.
     *
     * @param cents nuovo saldo in centesimi
     */
    public void setBalance(long cents) {
        longToBytes(cents, balance, (short) 0);
    }

    /**
     * Verifica che il saldo sia sufficiente per un pagamento.
     *
     * @param amountCents importo in centesimi
     * @return true se saldo >= amountCents
     */
    public boolean hasSufficientFunds(long amountCents) {
        return getBalance() >= amountCents;
    }

    /**
     * Verifica che il pagamento non superi il limite offline.
     *
     * @param amountCents importo in centesimi
     * @return true se il limite non verrebbe superato
     */
    public boolean isWithinOfflineLimit(long amountCents) {
        long spent = bytesToLong(offlineSpent, (short) 0);
        return (spent + amountCents) <= APDUConstants.OFFLINE_SPEND_LIMIT_CENTS;
    }

    /**
     * Deduce l'importo dal saldo e aggiorna l'accumulatore offline.
     * Chiamare solo dopo aver verificato disponibilità e limiti.
     *
     * @param amountCents importo in centesimi
     */
    public void debit(long amountCents) {
        long current = getBalance();
        setBalance(current - amountCents);

        long spent = bytesToLong(offlineSpent, (short) 0);
        longToBytes(spent + amountCents, offlineSpent, (short) 0);
    }

    /**
     * Accredita l'importo sul saldo.
     *
     * @param amountCents importo in centesimi
     */
    public void credit(long amountCents) {
        long current = getBalance();
        setBalance(current + amountCents);
    }

    /**
     * Azzera l'accumulatore di spesa offline (alla riconciliazione).
     */
    public void resetOfflineSpent() {
        Util.arrayFillNonAtomic(offlineSpent, (short) 0, APDUConstants.SIZE_BALANCE, (byte) 0);
    }

    // ─── Contatore ────────────────────────────────────────────────────────────

    /**
     * Incrementa il contatore monotonico (chiamare dopo ogni pagamento inviato).
     */
    public void incrementCounter() {
        counter.increment();
    }

    /**
     * Legge il valore corrente del contatore.
     */
    public long getCounterValue() {
        return counter.getValue();
    }

    /**
     * Copia il contatore nel buffer.
     */
    public void copyCounterTo(byte[] dest, short offset) {
        counter.copyTo(dest, offset);
    }

    /**
     * Verifica che il contatore ricevuto sia valido (anti-replay).
     */
    public boolean isValidIncomingCounter(byte[] data, short offset) {
        return counter.isValidIncoming(data, offset);
    }

    // ─── Log transazioni ──────────────────────────────────────────────────────

    /**
     * Registra una transazione nel log circolare.
     *
     * @param amountCents    importo in centesimi
     * @param counterVal     valore contatore al momento della transazione
     * @param remotePubKey   chiave pubblica della controparte (65 byte)
     * @param remotePkOffset offset nella chiave pubblica
     */
    public void logTransaction(long amountCents, long counterVal,
                               byte[] remotePubKey, short remotePkOffset) {
        short slot = (short) (txLogHead * TX_RECORD_SIZE);

        // Scrivi importo (8 byte)
        longToBytes(amountCents, txLog, slot);
        slot += APDUConstants.SIZE_BALANCE;

        // Scrivi contatore (4 byte, solo i 4 byte bassi del long)
        txLog[slot]     = (byte) ((counterVal >> 24) & 0xFF);
        txLog[(short)(slot+1)] = (byte) ((counterVal >> 16) & 0xFF);
        txLog[(short)(slot+2)] = (byte) ((counterVal >>  8) & 0xFF);
        txLog[(short)(slot+3)] = (byte) ( counterVal        & 0xFF);
        slot += APDUConstants.SIZE_COUNTER;

        // Scrivi chiave pubblica controparte (65 byte)
        Util.arrayCopy(remotePubKey, remotePkOffset, txLog, slot, APDUConstants.SIZE_PUBLIC_KEY);

        // Avanza la testa (log circolare)
        txLogHead = (short) ((txLogHead + 1) % APDUConstants.MAX_TX_LOG_SIZE);
        if (txLogCount < APDUConstants.MAX_TX_LOG_SIZE) {
            txLogCount++;
        }
    }

    /**
     * Copia un record del log nel buffer di output.
     *
     * @param index  indice (0 = più recente)
     * @param dest   buffer di destinazione
     * @param offset offset nel buffer
     * @return numero di byte copiati, oppure -1 se l'indice è fuori range
     */
    public short getTransactionLog(short index, byte[] dest, short offset) {
        if (index >= txLogCount) {
            return -1;
        }
        // Calcola la posizione nel log circolare (partendo dall'elemento più recente)
        short realIndex = (short) ((txLogHead - 1 - index + APDUConstants.MAX_TX_LOG_SIZE)
                                   % APDUConstants.MAX_TX_LOG_SIZE);
        short srcOffset = (short) (realIndex * TX_RECORD_SIZE);
        Util.arrayCopy(txLog, srcOffset, dest, offset, TX_RECORD_SIZE);
        return TX_RECORD_SIZE;
    }

    /** Numero di transazioni registrate nel log. */
    public short getTransactionCount() {
        return txLogCount;
    }

    // ─── Utility ──────────────────────────────────────────────────────────────

    private static long bytesToLong(byte[] buf, short off) {
        return ((long) (buf[off]     & 0xFF) << 56)
             | ((long) (buf[(short)(off+1)] & 0xFF) << 48)
             | ((long) (buf[(short)(off+2)] & 0xFF) << 40)
             | ((long) (buf[(short)(off+3)] & 0xFF) << 32)
             | ((long) (buf[(short)(off+4)] & 0xFF) << 24)
             | ((long) (buf[(short)(off+5)] & 0xFF) << 16)
             | ((long) (buf[(short)(off+6)] & 0xFF) <<  8)
             | ((long) (buf[(short)(off+7)] & 0xFF));
    }

    private static void longToBytes(long value, byte[] buf, short off) {
        buf[off]     = (byte) ((value >> 56) & 0xFF);
        buf[(short)(off+1)] = (byte) ((value >> 48) & 0xFF);
        buf[(short)(off+2)] = (byte) ((value >> 40) & 0xFF);
        buf[(short)(off+3)] = (byte) ((value >> 32) & 0xFF);
        buf[(short)(off+4)] = (byte) ((value >> 24) & 0xFF);
        buf[(short)(off+5)] = (byte) ((value >> 16) & 0xFF);
        buf[(short)(off+6)] = (byte) ((value >>  8) & 0xFF);
        buf[(short)(off+7)] = (byte) ( value         & 0xFF);
    }
}
