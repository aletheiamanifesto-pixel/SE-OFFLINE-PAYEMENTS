package ecb.deuro.offline;

import javacard.framework.*;
import javacard.security.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * MonotonicCounter — Contatore Anti-Manomissione
 * ═══════════════════════════════════════════════════════════════════
 *
 * ANALOGIA: IL CONTACHILOMETRI DELLA MACCHINA
 * ─────────────────────────────────────────────
 * Immagina il contachilometri di un'auto: può SOLO andare avanti,
 * mai indietro. Se qualcuno provasse a manometterlo, l'auto
 * smette di funzionare. Questo contatore funziona allo stesso modo.
 *
 * PERCHÉ SERVE?
 * ─────────────
 * Senza un contatore monotònico, un attaccante potrebbe:
 * 1. Copiare lo stato del chip PRIMA di un pagamento
 * 2. Fare il pagamento (spendere i soldi)
 * 3. Ripristinare lo stato precedente (come se non avesse pagato)
 * 4. Spendere gli stessi soldi di nuovo! (DOUBLE SPENDING)
 *
 * Il contatore impedisce questo: ogni transazione incrementa il
 * contatore, e il chip RIFIUTA qualsiasi stato con un contatore
 * inferiore a quello attuale. È IMPOSSIBILE tornare indietro.
 *
 * DETTAGLIO TECNICO: Il contatore è memorizzato in memoria
 * persistente (EEPROM/Flash) del Secure Element, protetta
 * da tamper-detection hardware. Qualsiasi tentativo fisico
 * di modificare la memoria distrugge il chip.
 */
public class MonotonicCounter {

    // ─────────────────────────────────────────────────────────
    // Il valore del contatore — memorizzato in modo persistente.
    // Usiamo un array di byte (4 byte = 32 bit) perché Java Card
    // non supporta long, e short (16 bit) sarebbe troppo piccolo
    // (max 65535 transazioni, esaurito in pochi mesi di uso).
    //
    // Con 4 byte: max 4.294.967.295 transazioni — sufficiente
    // per una vita intera di pagamenti.
    // ─────────────────────────────────────────────────────────
    private byte[] counterValue;

    /** Lunghezza del contatore in byte */
    private static final short COUNTER_LENGTH = (short) 4;

    /**
     * Costruttore — inizializza il contatore a zero.
     *
     * NOTA IMPORTANTE: Usiamo JCSystem.makeTransientByteArray() NO!
     * Dobbiamo usare un array PERSISTENTE perché il contatore
     * deve sopravvivere allo spegnimento del chip.
     * Se fosse transiente, si azzererebbe ad ogni riavvio,
     * vanificando tutta la protezione anti-replay.
     */
    public MonotonicCounter() {
        // Array persistente in EEPROM — sopravvive ai riavvii
        counterValue = new byte[COUNTER_LENGTH];
        // Inizializzato a 0x00000000 automaticamente da Java Card
    }

    /**
     * Incrementa il contatore di 1.
     *
     * ANALOGIA: Ogni volta che fai un viaggio in macchina,
     * il contachilometri avanza. Non puoi impedirlo.
     *
     * PERCHÉ increment() e non setValue()?
     * Perché permettere di impostare un valore arbitrario
     * aprirebbe la porta a manipolazioni. L'unica operazione
     * permessa è "avanza di 1". Punto.
     *
     * ATOMICITÀ: Questa operazione DEVE essere dentro una
     * transazione JCSystem per garantire che, se il chip
     * si spegne a metà, il contatore non resti in uno stato
     * inconsistente.
     *
     * @return true se l'incremento è riuscito, false se overflow
     */
    public boolean increment() {
        // Incremento manuale big-endian (byte più significativo prima)
        // Partiamo dal byte meno significativo (indice 3)
        for (short i = (short)(COUNTER_LENGTH - 1); i >= 0; i--) {
            // Incrementa il byte corrente
            counterValue[i]++;

            // Se non c'è overflow (il byte non è tornato a 0x00),
            // abbiamo finito
            if (counterValue[i] != (byte) 0x00) {
                return true;
            }
            // Se c'è overflow, il carry si propaga al byte successivo
            // (come quando 99 diventa 100: il 9 diventa 0 e si porta l'1)
        }

        // Se arriviamo qui, TUTTI i byte sono andati in overflow:
        // il contatore è tornato a 0x00000000 dopo 0xFFFFFFFF.
        // Questo non dovrebbe MAI succedere in pratica (4 miliardi di TX).
        // Per sicurezza, blocchiamo il chip.
        return false;
    }

    /**
     * Restituisce il valore corrente del contatore.
     *
     * @param dest    buffer di destinazione
     * @param offset  posizione nel buffer dove scrivere
     * @return numero di byte scritti (sempre 4)
     */
    public short getValue(byte[] dest, short offset) {
        Util.arrayCopy(counterValue, (short) 0, dest, offset, COUNTER_LENGTH);
        return COUNTER_LENGTH;
    }

    /**
     * Verifica che un valore di contatore sia MAGGIORE di quello attuale.
     *
     * ANALOGIA: Come verificare che il contachilometri di un'auto
     * usata mostri un valore SUPERIORE a quello dell'ultimo controllo.
     * Se è inferiore, qualcuno ha manomesso il contachilometri!
     *
     * @param expected  il valore atteso (deve essere > valore attuale)
     * @param offset    posizione nel buffer
     * @return true se expected > valore attuale
     */
    public boolean isGreaterThan(byte[] expected, short offset) {
        for (short i = 0; i < COUNTER_LENGTH; i++) {
            // Confronto unsigned byte per byte (dal più significativo)
            short current = (short)(counterValue[i] & 0xFF);
            short other = (short)(expected[(short)(offset + i)] & 0xFF);

            if (other > current) return true;
            if (other < current) return false;
            // Se uguali, continua con il byte successivo
        }
        // Se tutti uguali, NON è maggiore
        return false;
    }

    /**
     * Restituisce la lunghezza del contatore in byte.
     */
    public short getLength() {
        return COUNTER_LENGTH;
    }
}
