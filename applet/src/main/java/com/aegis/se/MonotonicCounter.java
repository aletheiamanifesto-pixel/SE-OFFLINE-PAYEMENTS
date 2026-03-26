package com.aegis.se;

/**
 * Contatore monotonico anti-frode.
 *
 * Il contatore è memorizzato in EEPROM (memoria non volatile) e può
 * solo aumentare. Non esiste un'operazione di decremento. Questo garantisce
 * protezione contro gli attacchi replay: un pacchetto con un contatore
 * già visto viene automaticamente rifiutato.
 *
 * Analogia: è come il numero progressivo di un assegno bancario.
 * Se hai già incassato l'assegno n.42, un secondo assegno n.42 è rifiutato.
 */
public class MonotonicCounter {

    /** Valore corrente del contatore (4 byte in EEPROM). */
    private final byte[] counterBytes;

    /** Offset del valore nel byte array. */
    private static final short OFFSET = 0;

    /** Dimensione del contatore in byte (uint32). */
    private static final short LENGTH = 4;

    /**
     * Crea un nuovo contatore e lo inizializza a zero.
     * L'allocazione avviene in memoria EEPROM (persistente).
     */
    public MonotonicCounter() {
        // Allocazione in memoria persistente (EEPROM): sopravvive al deselect e al reset
        counterBytes = new byte[LENGTH];
        reset();
    }

    /**
     * Resetta il contatore a zero (solo al momento della creazione).
     * Non chiamare dopo l'inizializzazione: usa solo incrementCounter().
     */
    private void reset() {
        counterBytes[0] = 0;
        counterBytes[1] = 0;
        counterBytes[2] = 0;
        counterBytes[3] = 0;
    }

    /**
     * Incrementa il contatore di 1 (operazione atomica nel chip).
     * Questo è l'unico modo per modificare il contatore.
     *
     * @throws javacard.framework.ISOException se il contatore raggiunge il massimo uint32
     */
    public void increment() {
        // Incremento big-endian: parte dal byte meno significativo
        for (short i = (short) (LENGTH - 1); i >= 0; i--) {
            if (++counterBytes[i] != 0) {
                break; // nessun riporto, fine
            }
            // Se siamo qui c'è un riporto: il byte è tornato a 0,
            // continua con il byte precedente
        }
    }

    /**
     * Legge il valore corrente del contatore come intero a 32 bit senza segno.
     *
     * @return valore contatore (0 … 4.294.967.295)
     */
    public long getValue() {
        return ((long) (counterBytes[0] & 0xFF) << 24)
             | ((long) (counterBytes[1] & 0xFF) << 16)
             | ((long) (counterBytes[2] & 0xFF) << 8)
             | ((long) (counterBytes[3] & 0xFF));
    }

    /**
     * Copia il valore del contatore nel buffer di output.
     *
     * @param dest   buffer di destinazione
     * @param offset offset nel buffer
     */
    public void copyTo(byte[] dest, short offset) {
        dest[offset]     = counterBytes[0];
        dest[(short)(offset + 1)] = counterBytes[1];
        dest[(short)(offset + 2)] = counterBytes[2];
        dest[(short)(offset + 3)] = counterBytes[3];
    }

    /**
     * Verifica che il contatore ricevuto dall'esterno sia strettamente
     * maggiore dell'ultimo valore noto (protezione anti-replay).
     *
     * @param receivedBytes array contenente il contatore ricevuto (4 byte big-endian)
     * @param offset        offset nell'array
     * @return true se il contatore ricevuto è valido (> valore attuale)
     */
    public boolean isValidIncoming(byte[] receivedBytes, short offset) {
        long received = ((long) (receivedBytes[offset] & 0xFF) << 24)
                      | ((long) (receivedBytes[(short)(offset + 1)] & 0xFF) << 16)
                      | ((long) (receivedBytes[(short)(offset + 2)] & 0xFF) << 8)
                      | ((long) (receivedBytes[(short)(offset + 3)] & 0xFF));
        return received > getValue();
    }
}
