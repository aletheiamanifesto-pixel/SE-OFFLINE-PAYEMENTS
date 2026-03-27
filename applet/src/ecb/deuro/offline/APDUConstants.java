package ecb.deuro.offline;

/**
 * ═══════════════════════════════════════════════════════════════════
 * APDUConstants — Costanti per i comandi APDU del sistema AEGIS
 * ═══════════════════════════════════════════════════════════════════
 *
 * ANALOGIA: Immagina le APDU come LETTERE POSTALI standardizzate.
 * Ogni lettera ha: mittente (CLA), tipo di richiesta (INS),
 * parametri (P1, P2), e il contenuto (Data).
 *
 * Questo file definisce tutte le "etichette" standard usate
 * nella comunicazione tra il telefono e il chip sicuro.
 *
 * PERCHÉ un file separato? Perché le costanti devono essere
 * condivise tra tutte le classi e avere un unico punto di verità.
 */
public class APDUConstants {

    // ═══════════════════════════════════════════════════════════
    // CLA — Classe del comando (il "tipo di busta")
    // ═══════════════════════════════════════════════════════════

    /**
     * CLA standard ISO 7816 — usato per comandi generici come SELECT.
     * È come una busta bianca standard delle poste.
     */
    public static final byte CLA_ISO7816 = (byte) 0x00;

    /**
     * CLA proprietario — usato per i nostri comandi personalizzati.
     * È come una busta con il logo AEGIS: identifica i NOSTRI comandi.
     * Il valore 0x80 indica "comando proprietario" nello standard ISO.
     */
    public static final byte CLA_PROPRIETARIO = (byte) 0x80;

    // ═══════════════════════════════════════════════════════════
    // INS — Istruzione (il "tipo di richiesta" nella lettera)
    // ═══════════════════════════════════════════════════════════

    /**
     * SELECT — Seleziona l'applet sul chip.
     * ANALOGIA: È come entrare in banca e dire "voglio parlare
     * con lo sportello pagamenti", prima di fare qualsiasi operazione.
     */
    public static final byte INS_SELECT = (byte) 0xA4;

    /**
     * GET_BALANCE — Richiedi il saldo corrente.
     * ANALOGIA: Chiedere al cassiere "quanto ho nel conto?"
     * Restituisce 4 byte con il saldo in centesimi.
     */
    public static final byte INS_GET_BALANCE = (byte) 0x10;

    /**
     * DEBIT — Addebita un importo dal portafoglio.
     * ANALOGIA: Prelevare contante dal bancomat.
     * Il dato contiene l'importo in centesimi (4 byte, big-endian).
     * INCREMENTA il contatore monotònico (anti-replay).
     */
    public static final byte INS_DEBIT = (byte) 0x20;

    /**
     * CREDIT — Accredita un importo al portafoglio.
     * ANALOGIA: Depositare contante in cassaforte.
     * Il dato contiene l'importo in centesimi (4 byte, big-endian).
     */
    public static final byte INS_CREDIT = (byte) 0x30;

    /**
     * GET_COUNTER — Leggi il valore del contatore monotònico.
     * ANALOGIA: Leggere il contachilometri della macchina.
     * Serve per verificare che non ci siano state manomissioni.
     */
    public static final byte INS_GET_COUNTER = (byte) 0x40;

    /**
     * SIGN — Firma digitale dei dati con chiave privata ECDSA.
     * ANALOGIA: Il notaio che mette il timbro su un documento.
     * La firma prova che la transazione è avvenuta davvero.
     */
    public static final byte INS_SIGN = (byte) 0x50;

    /**
     * GET_CERTIFICATE — Ottieni il certificato (chiave pubblica).
     * ANALOGIA: Chiedere la carta d'identità per verificare chi sei.
     */
    public static final byte INS_GET_CERTIFICATE = (byte) 0x60;

    /**
     * MUTUAL_AUTH — Autenticazione reciproca tra due chip.
     * ANALOGIA: Due persone che si mostrano i documenti a vicenda
     * prima di iniziare un affare. Entrambi devono fidarsi.
     */
    public static final byte INS_MUTUAL_AUTH = (byte) 0x70;

    // ═══════════════════════════════════════════════════════════
    // Status Word — La "risposta" del chip (successo/errore)
    // ═══════════════════════════════════════════════════════════

    /**
     * SW_OK (0x9000) — Tutto bene! Operazione completata.
     * ANALOGIA: Il cassiere dice "operazione riuscita, ecco la ricevuta".
     */
    public static final short SW_OK = (short) 0x9000;

    /**
     * SW_WRONG_PIN (0x6983) — PIN/autenticazione errata.
     * ANALOGIA: "Mi dispiace, la password è sbagliata."
     */
    public static final short SW_WRONG_PIN = (short) 0x6983;

    /**
     * SW_INSUFFICIENT_BALANCE (0x6985) — Saldo insufficiente.
     * ANALOGIA: "Non hai abbastanza soldi per questa operazione."
     */
    public static final short SW_INSUFFICIENT_BALANCE = (short) 0x6985;

    /**
     * SW_WRONG_LENGTH (0x6700) — Lunghezza dati non valida.
     * ANALOGIA: "La lettera che mi hai mandato ha il formato sbagliato."
     */
    public static final short SW_WRONG_LENGTH = (short) 0x6700;

    /**
     * SW_INS_NOT_SUPPORTED (0x6D00) — Comando non riconosciuto.
     * ANALOGIA: "Non capisco cosa mi stai chiedendo."
     */
    public static final short SW_INS_NOT_SUPPORTED = (short) 0x6D00;

    /**
     * SW_CONDITIONS_NOT_SATISFIED (0x6985) — Condizioni non soddisfatte.
     * ANALOGIA: "Non puoi fare questa operazione adesso."
     */
    public static final short SW_CONDITIONS_NOT_SATISFIED = (short) 0x6985;

    // ═══════════════════════════════════════════════════════════
    // AID — Application Identifier (l'indirizzo dell'applet)
    // ═══════════════════════════════════════════════════════════

    /**
     * L'AID identifica univocamente la nostra applicazione sul chip.
     * ANALOGIA: È come il codice fiscale dell'applicazione —
     * unico al mondo, registrato presso l'ente certificatore.
     *
     * Formato: RID (5 byte, registrato) + PIX (fino a 11 byte, libero)
     * Il nostro: 0xA0000000041010 = ECB Digital Euro Offline
     */
    public static final byte[] APPLET_AID = {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x04, (byte) 0x10, (byte) 0x10
    };

    /**
     * Costruttore privato — questa classe non va istanziata.
     * Contiene solo costanti statiche.
     */
    private APDUConstants() {
        // Nessuna istanziazione permessa
    }
}
