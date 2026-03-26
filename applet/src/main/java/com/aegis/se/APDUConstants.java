package com.aegis.se;

/**
 * Costanti APDU per l'applet OfflineDigitalEuro.
 *
 * CLA = 0x80 (comandi proprietari)
 * Ogni INS identifica un comando specifico.
 */
public final class APDUConstants {

    // ─── CLA ──────────────────────────────────────────────────────────────────

    /** Classe comandi proprietari AEGIS. */
    public static final byte CLA_AEGIS = (byte) 0x80;

    // ─── INS — Comandi ────────────────────────────────────────────────────────

    /** Legge il saldo corrente in centesimi (risposta: 8 byte big-endian). */
    public static final byte INS_GET_BALANCE = (byte) 0x20;

    /** Restituisce la chiave pubblica ECDSA (65 byte, formato non compresso). */
    public static final byte INS_GET_PUBLIC_KEY = (byte) 0x30;

    /**
     * Avvia un pagamento: riceve importo + chiave_pubblica_bob + contatore_bob.
     * Restituisce: chiave_pubblica_alice + contatore_alice + firma_ECDSA.
     */
    public static final byte INS_INITIATE_PAYMENT = (byte) 0x40;

    /**
     * Elabora il pagamento ricevuto: verifica firma Alice e aggiorna saldo Bob.
     * Restituisce: nuovo saldo Bob (8 byte).
     */
    public static final byte INS_PROCESS_PAYMENT = (byte) 0x50;

    /**
     * Conferma il pagamento: Alice aggiorna il proprio saldo dopo conferma Bob.
     * Restituisce: nuovo saldo Alice (8 byte).
     */
    public static final byte INS_CONFIRM_PAYMENT = (byte) 0x60;

    /** Legge il contatore monotonico corrente (4 byte big-endian). */
    public static final byte INS_GET_COUNTER = (byte) 0x70;

    /**
     * Legge il log delle ultime transazioni.
     * P1 = indice transazione (0 = più recente).
     */
    public static final byte INS_GET_TRANSACTION_LOG = (byte) 0x80;

    /**
     * Carica fondi nel portafoglio (richiede firma CA).
     * Solo online, verificato dalla blockchain AEGIS.
     */
    public static final byte INS_LOAD_FUNDS = (byte) 0xA0;

    // ─── Status Words ─────────────────────────────────────────────────────────

    /** Successo. */
    public static final short SW_OK = (short) 0x9000;

    /** Saldo insufficiente per il pagamento richiesto. */
    public static final short SW_INSUFFICIENT_FUNDS = (short) 0x9110;

    /** Contatore non valido — possibile attacco replay. */
    public static final short SW_INVALID_COUNTER = (short) 0x9120;

    /** Firma ECDSA non valida. */
    public static final short SW_INVALID_SIGNATURE = (short) 0x9130;

    /** Importo non valido (zero o negativo). */
    public static final short SW_INVALID_AMOUNT = (short) 0x9140;

    /** Limite di spesa offline superato. */
    public static final short SW_OFFLINE_LIMIT_EXCEEDED = (short) 0x9150;

    /** Limite temporale offline superato (richiede riconciliazione). */
    public static final short SW_TEMPORAL_LIMIT_EXCEEDED = (short) 0x9160;

    /** Log transazioni pieno. */
    public static final short SW_LOG_FULL = (short) 0x9170;

    // ─── AID ──────────────────────────────────────────────────────────────────

    /** Application Identifier dell'applet AEGIS Euro. */
    public static final byte[] AID = {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x08,
        (byte) 0x48, (byte) 0x41, (byte) 0x45, (byte) 0x47,
        (byte) 0x01, (byte) 0x00
    };

    // ─── Dimensioni dati ──────────────────────────────────────────────────────

    /** Dimensione saldo in byte (uint64 big-endian). */
    public static final short SIZE_BALANCE = 8;

    /** Dimensione contatore in byte (uint32 big-endian). */
    public static final short SIZE_COUNTER = 4;

    /** Dimensione chiave pubblica ECDSA non compressa (0x04 || X || Y). */
    public static final short SIZE_PUBLIC_KEY = 65;

    /** Dimensione massima firma ECDSA DER. */
    public static final short SIZE_SIGNATURE_MAX = 72;

    /** Dimensione header transazione (importo + cnt). */
    public static final short SIZE_TX_HEADER = SIZE_BALANCE + SIZE_COUNTER; // 12

    // ─── Limiti ───────────────────────────────────────────────────────────────

    /** Limite massimo spesa offline in centesimi (500.00€). */
    public static final long OFFLINE_SPEND_LIMIT_CENTS = 50000L;

    /** Numero massimo di transazioni nel log locale del chip. */
    public static final short MAX_TX_LOG_SIZE = 10;

    // Costruttore privato: classe di sole costanti, non istanziabile.
    private APDUConstants() {}
}
