package ecb.deuro.offline;

import javacard.framework.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * WalletState — Stato del Portafoglio Digitale sul Chip
 * ═══════════════════════════════════════════════════════════════════
 *
 * ANALOGIA: IL LIBRETTO DI RISPARMIO IN UNA CASSAFORTE
 * ─────────────────────────────────────────────────────
 * Immagina un libretto di risparmio chiuso dentro una cassaforte
 * blindata (il Secure Element). Sul libretto c'è scritto:
 * - Quanto hai (saldo)
 * - In che valuta (EUR)
 * - Il tuo nome/codice (wallet ID)
 * - Se il libretto è stato attivato
 * - Il limite massimo per operazione
 *
 * Nessuno può leggere o modificare il libretto senza la chiave
 * della cassaforte. Anche tu, il proprietario, puoi solo fare
 * operazioni AUTORIZZATE (deposito, prelievo), mai modificare
 * direttamente i numeri.
 *
 * PERCHÉ una classe separata?
 * Separare lo stato dalla logica è un principio fondamentale
 * della buona programmazione. WalletState gestisce SOLO i dati,
 * l'applet principale gestisce la LOGICA di business.
 */
public class WalletState {

    // ═══════════════════════════════════════════════════════════
    // SALDO — Il cuore del portafoglio
    // ═══════════════════════════════════════════════════════════

    /**
     * Saldo corrente in CENTESIMI di euro.
     * PERCHÉ centesimi? Perché Java Card non supporta numeri decimali
     * (float/double). Usando centesimi evitiamo errori di arrotondamento.
     * Esempio: 100.00€ = 10000 centesimi.
     *
     * Tipo short: range -32768 a 32767 → max 327.67€
     * Per importi maggiori servirebbe un array di byte (come il contatore).
     * Per un prototipo educativo, short è sufficiente.
     */
    private short balance;

    // ═══════════════════════════════════════════════════════════
    // CODICE VALUTA — Identifica la moneta
    // ═══════════════════════════════════════════════════════════

    /**
     * Codice valuta ISO 4217 numerico.
     * EUR = 978. Serve per evitare di mischiare euro con dollari
     * o altre valute. Il chip accetta SOLO operazioni nella valuta
     * con cui è stato inizializzato.
     */
    private short currencyCode;

    /** Codice ISO 4217 per Euro */
    public static final short CURRENCY_EUR = (short) 978;

    // ═══════════════════════════════════════════════════════════
    // WALLET ID — Identificativo univoco del portafoglio
    // ═══════════════════════════════════════════════════════════

    /**
     * ID univoco del portafoglio (16 byte).
     * ANALOGIA: È come il codice IBAN del tuo conto —
     * identifica univocamente il TUO portafoglio nel sistema.
     * Generato una sola volta durante l'inizializzazione.
     */
    private byte[] walletId;

    /** Lunghezza dell'ID portafoglio */
    private static final short WALLET_ID_LENGTH = (short) 16;

    // ═══════════════════════════════════════════════════════════
    // FLAG DI INIZIALIZZAZIONE
    // ═══════════════════════════════════════════════════════════

    /**
     * Indica se il portafoglio è stato inizializzato.
     * PERCHÉ serve? Un chip appena prodotto è "vuoto".
     * Prima di poterlo usare, deve essere inizializzato con
     * saldo, valuta e chiavi crittografiche. Questa flag
     * impedisce di usare un chip non configurato.
     *
     * ANALOGIA: Come attivare una carta di credito nuova —
     * prima della prima telefonata di attivazione, non funziona.
     */
    private boolean isInitialized;

    // ═══════════════════════════════════════════════════════════
    // LIMITE TRANSAZIONE — Protezione anti-frode
    // ═══════════════════════════════════════════════════════════

    /**
     * Importo massimo per singola transazione (in centesimi).
     * ANALOGIA: Come il limite giornaliero del bancomat.
     * Anche se hai 10.000€, non puoi prelevare più di 1.000€
     * in una volta. Limita i danni in caso di furto.
     *
     * Default: 50000 centesimi = 500.00€
     */
    private short maxTransactionLimit;

    /** Limite di default: 500.00€ */
    public static final short DEFAULT_MAX_TX_LIMIT = (short) 50000;

    // ═══════════════════════════════════════════════════════════
    // COSTRUTTORE
    // ═══════════════════════════════════════════════════════════

    /**
     * Crea un nuovo stato portafoglio (non ancora inizializzato).
     * Tutti i campi sono in memoria PERSISTENTE (EEPROM).
     */
    public WalletState() {
        this.balance = (short) 0;
        this.currencyCode = CURRENCY_EUR;
        this.walletId = new byte[WALLET_ID_LENGTH];
        this.isInitialized = false;
        this.maxTransactionLimit = DEFAULT_MAX_TX_LIMIT;
    }

    // ═══════════════════════════════════════════════════════════
    // METODI DI ACCESSO AL SALDO
    // ═══════════════════════════════════════════════════════════

    /**
     * Restituisce il saldo corrente in centesimi.
     */
    public short getBalance() {
        return balance;
    }

    /**
     * Addebita un importo dal saldo.
     *
     * @param amount importo in centesimi (deve essere > 0)
     * @return true se l'operazione è riuscita
     * @throws ISOException se saldo insufficiente o importo non valido
     */
    public boolean debit(short amount) {
        // Verifiche di sicurezza
        if (amount <= 0) {
            ISOException.throwIt(APDUConstants.SW_WRONG_LENGTH);
        }
        if (amount > maxTransactionLimit) {
            ISOException.throwIt(APDUConstants.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (amount > balance) {
            ISOException.throwIt(APDUConstants.SW_INSUFFICIENT_BALANCE);
        }

        // Sottrai dal saldo
        balance -= amount;
        return true;
    }

    /**
     * Accredita un importo al saldo.
     *
     * @param amount importo in centesimi (deve essere > 0)
     * @return true se l'operazione è riuscita
     */
    public boolean credit(short amount) {
        if (amount <= 0) {
            ISOException.throwIt(APDUConstants.SW_WRONG_LENGTH);
        }

        // Verifica overflow: il saldo non può superare Short.MAX_VALUE
        if ((short)(balance + amount) < balance) {
            ISOException.throwIt(APDUConstants.SW_CONDITIONS_NOT_SATISFIED);
        }

        balance += amount;
        return true;
    }

    // ═══════════════════════════════════════════════════════════
    // METODI DI INIZIALIZZAZIONE E STATO
    // ═══════════════════════════════════════════════════════════

    /**
     * Inizializza il portafoglio con saldo iniziale e ID.
     * Può essere chiamato UNA SOLA VOLTA.
     *
     * @param initialBalance saldo iniziale in centesimi
     * @param id             buffer con l'ID del portafoglio
     * @param idOffset       posizione nel buffer
     */
    public void initialize(short initialBalance, byte[] id, short idOffset) {
        if (isInitialized) {
            // GIÀ inizializzato — operazione non permessa
            ISOException.throwIt(APDUConstants.SW_CONDITIONS_NOT_SATISFIED);
        }

        this.balance = initialBalance;
        Util.arrayCopy(id, idOffset, walletId, (short) 0, WALLET_ID_LENGTH);
        this.isInitialized = true;
    }

    /**
     * Verifica se il portafoglio è inizializzato e pronto all'uso.
     */
    public boolean isReady() {
        return isInitialized;
    }

    /**
     * Restituisce il codice valuta.
     */
    public short getCurrencyCode() {
        return currencyCode;
    }

    /**
     * Copia l'ID del portafoglio nel buffer di destinazione.
     *
     * @param dest   buffer di destinazione
     * @param offset posizione nel buffer
     * @return numero di byte copiati
     */
    public short getWalletId(byte[] dest, short offset) {
        Util.arrayCopy(walletId, (short) 0, dest, offset, WALLET_ID_LENGTH);
        return WALLET_ID_LENGTH;
    }

    /**
     * Restituisce il limite massimo per transazione.
     */
    public short getMaxTransactionLimit() {
        return maxTransactionLimit;
    }
}
