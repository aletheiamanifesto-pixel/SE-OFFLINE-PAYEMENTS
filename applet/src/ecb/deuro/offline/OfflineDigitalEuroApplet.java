package ecb.deuro.offline;

import javacard.framework.*;
import javacard.security.*;

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * OfflineDigitalEuroApplet — Applet Principale per Pagamenti Offline AEGIS
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * ANALOGIA: LA CASSAFORTE INTELLIGENTE
 * ─────────────────────────────────────
 * Immagina una cassaforte che non solo custodisce i tuoi soldi,
 * ma sa anche CONTARE, FIRMARE ricevute e RIFIUTARE operazioni
 * sospette. Questa cassaforte vive dentro il chip NFC del telefono
 * ed è IMPOSSIBILE da aprire o manomettere.
 *
 * COME FUNZIONA UN PAGAMENTO:
 * ──────────────────────────
 *   FASE 1 → Autenticazione reciproca (chi sei?)
 *   FASE 2 → Verifica saldo (hai abbastanza soldi?)
 *   FASE 3 → Trasferimento atomico (tutto o niente!)
 *   FASE 4 → Firma e ricevuta (prova che è successo)
 *
 * "ATOMICO" significa che il pagamento O va a buon fine completamente,
 * O non succede niente. Non può restare "a metà". Come un interruttore:
 * acceso o spento, mai nel mezzo.
 *
 * FLUSSO APDU:
 * ───────────
 * Il telefono comunica con il chip tramite comandi APDU (Application
 * Protocol Data Unit). Ogni comando è una "lettera" con formato standard:
 *
 *   [CLA] [INS] [P1] [P2] [Lc] [Data...] [Le]
 *    │     │     │    │    │     │          └─ Quanti byte aspetti in risposta
 *    │     │     │    │    │     └─ I dati del comando
 *    │     │     │    │    └─ Lunghezza dei dati
 *    │     │     │    └─ Parametro 2
 *    │     │     └─ Parametro 1
 *    │     └─ Istruzione (cosa vuoi fare)
 *    └─ Classe (tipo di comando)
 */
public class OfflineDigitalEuroApplet extends Applet {

    // ═══════════════════════════════════════════════════════════
    // COMPONENTI INTERNI — I "reparti" della cassaforte
    // ═══════════════════════════════════════════════════════════

    /** Lo stato del portafoglio (saldo, ID, valuta) */
    private WalletState wallet;

    /** Il contatore anti-manomissione (contachilometri) */
    private MonotonicCounter counter;

    /** Il gestore crittografico (il notaio) */
    private CryptoManager crypto;

    /** Flag: autenticazione reciproca completata */
    private boolean isAuthenticated;

    /** Buffer temporaneo per elaborazione APDU */
    private byte[] workBuffer;

    /** Dimensione del buffer di lavoro */
    private static final short WORK_BUFFER_SIZE = (short) 256;

    // ═══════════════════════════════════════════════════════════
    // INSTALLAZIONE — Quando il chip viene "preparato"
    // ═══════════════════════════════════════════════════════════

    /**
     * Costruttore privato — chiamato SOLO da install().
     *
     * PERCHÉ privato? Perché in Java Card l'installazione segue
     * un protocollo preciso gestito dal sistema operativo del chip.
     * Non si può creare un applet "a mano".
     *
     * @param bArray  buffer con parametri di installazione
     * @param bOffset posizione iniziale
     * @param bLength lunghezza dei parametri
     */
    private OfflineDigitalEuroApplet(byte[] bArray, short bOffset, byte bLength) {
        // Crea i componenti interni
        wallet = new WalletState();
        counter = new MonotonicCounter();
        crypto = new CryptoManager();

        // Buffer temporaneo — TRANSIENTE (si cancella ad ogni sessione)
        // per motivi di sicurezza: non lasciamo dati sensibili in memoria
        workBuffer = JCSystem.makeTransientByteArray(
            WORK_BUFFER_SIZE,
            JCSystem.CLEAR_ON_DESELECT
        );

        isAuthenticated = false;

        // Registra l'applet con il suo AID (identificativo unico)
        register();
    }

    /**
     * Metodo di installazione — chiamato dal sistema operativo
     * quando l'applet viene caricato sul chip per la prima volta.
     *
     * ANALOGIA: È come l'inaugurazione di una nuova filiale bancaria.
     * Si prepara tutto (cassaforte, timbri, registri) prima di aprire.
     *
     * @param bArray  parametri di installazione dal GlobalPlatform
     * @param bOffset posizione nel buffer
     * @param bLength lunghezza dei parametri
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new OfflineDigitalEuroApplet(bArray, bOffset, bLength);
    }

    // ═══════════════════════════════════════════════════════════
    // PROCESS — Il "centralino" che smista le richieste
    // ═══════════════════════════════════════════════════════════

    /**
     * Metodo principale — riceve OGNI comando APDU dal telefono.
     *
     * ANALOGIA: È come il centralino di una banca. Ogni telefonata
     * (comando APDU) arriva qui, e il centralino decide a quale
     * reparto inoltrarla in base al tipo di richiesta.
     *
     * @param apdu l'oggetto APDU con il comando ricevuto
     */
    public void process(APDU apdu) {
        // Ignora il comando SELECT del sistema operativo
        // (viene mandato automaticamente quando si "apre" l'applet)
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        // Verifica la classe del comando
        if (cla != APDUConstants.CLA_PROPRIETARIO) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // ─────────────────────────────────────────────────────
        // Smista il comando al reparto giusto
        // ─────────────────────────────────────────────────────
        switch (ins) {
            case APDUConstants.INS_GET_BALANCE:
                processGetBalance(apdu);
                break;

            case APDUConstants.INS_DEBIT:
                processDebit(apdu);
                break;

            case APDUConstants.INS_CREDIT:
                processCredit(apdu);
                break;

            case APDUConstants.INS_GET_COUNTER:
                processGetCounter(apdu);
                break;

            case APDUConstants.INS_SIGN:
                processSign(apdu);
                break;

            case APDUConstants.INS_GET_CERTIFICATE:
                processGetCertificate(apdu);
                break;

            case APDUConstants.INS_MUTUAL_AUTH:
                processMutualAuth(apdu);
                break;

            default:
                // Comando sconosciuto — rifiuta
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // GESTORI DEI SINGOLI COMANDI
    // ═══════════════════════════════════════════════════════════

    /**
     * GET_BALANCE — Restituisce il saldo corrente.
     *
     * Risposta: 4 byte big-endian con il saldo in centesimi.
     * Esempio: saldo 100.00€ → 0x00 0x00 0x27 0x10 (10000 dec)
     */
    private void processGetBalance(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short balance = wallet.getBalance();

        // Scrive il saldo come 4 byte big-endian
        buffer[0] = (byte) 0x00;
        buffer[1] = (byte) 0x00;
        buffer[2] = (byte) ((balance >> 8) & 0xFF);
        buffer[3] = (byte) (balance & 0xFF);

        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }

    /**
     * DEBIT — Addebita un importo (OPERAZIONE ATOMICA).
     *
     * FASE CRITICA: Questa è l'operazione più delicata.
     * Usa JCSystem.beginTransaction() per garantire atomicità:
     * se il chip si spegne a metà (NFC interrotto), TUTTO viene
     * annullato automaticamente. Nessun soldo va perso.
     *
     * ANALOGIA: È come un bonifico bancario — o passa tutto,
     * o non passa niente. Non puoi restare con metà dei soldi
     * trasferiti e metà no.
     *
     * Dati in ingresso: 4 byte big-endian con importo in centesimi.
     */
    private void processDebit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        // Verifica lunghezza dati: servono esattamente 4 byte
        if (bytesRead != (short) 4) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Estrai l'importo dai 4 byte big-endian
        short amount = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA + 2));

        // ══════════════════════════════════════════════════════
        // INIZIO TRANSAZIONE ATOMICA
        // Se qualcosa va storto da qui in poi, il chip annulla
        // TUTTO automaticamente (rollback).
        // ══════════════════════════════════════════════════════
        JCSystem.beginTransaction();

        try {
            // 1. Addebita dal saldo
            wallet.debit(amount);

            // 2. Incrementa il contatore monotònico
            //    (FONDAMENTALE per anti-double-spending)
            if (!counter.increment()) {
                // Overflow del contatore — situazione critica
                JCSystem.abortTransaction();
                ISOException.throwIt(APDUConstants.SW_CONDITIONS_NOT_SATISFIED);
            }

            // 3. Tutto ok — conferma la transazione
            JCSystem.commitTransaction();

        } catch (ISOException e) {
            // Errore — annulla TUTTO (saldo e contatore tornano come prima)
            if (JCSystem.getTransactionDepth() > 0) {
                JCSystem.abortTransaction();
            }
            ISOException.throwIt(e.getReason());
        }
        // ══════════════════════════════════════════════════════
        // FINE TRANSAZIONE ATOMICA
        // ══════════════════════════════════════════════════════
    }

    /**
     * CREDIT — Accredita un importo al portafoglio.
     * Anche questa operazione è atomica per sicurezza.
     */
    private void processCredit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        if (bytesRead != (short) 4) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short amount = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA + 2));

        JCSystem.beginTransaction();
        try {
            wallet.credit(amount);
            JCSystem.commitTransaction();
        } catch (ISOException e) {
            if (JCSystem.getTransactionDepth() > 0) {
                JCSystem.abortTransaction();
            }
            ISOException.throwIt(e.getReason());
        }
    }

    /**
     * GET_COUNTER — Restituisce il valore del contatore monotònico.
     * Serve per verifiche di integrità e anti-replay.
     */
    private void processGetCounter(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = counter.getValue(buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * SIGN — Firma digitale dei dati della transazione.
     *
     * Il pagatore firma i dettagli della transazione (importo,
     * contatore, timestamp) con la sua chiave privata ECDSA.
     * Questa firma è la "ricevuta digitale" che prova
     * che il pagamento è avvenuto davvero.
     *
     * ANALOGIA: Come la firma sulla ricevuta del POS —
     * prova che TU hai autorizzato quel pagamento.
     */
    private void processSign(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        // Firma i dati ricevuti
        short sigLen = crypto.sign(
            buffer, ISO7816.OFFSET_CDATA, bytesRead,
            workBuffer, (short) 0
        );

        // Copia la firma nel buffer di uscita
        Util.arrayCopy(workBuffer, (short) 0, buffer, (short) 0, sigLen);
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    /**
     * GET_CERTIFICATE — Restituisce la chiave pubblica.
     *
     * La controparte usa questa chiave per verificare le firme.
     * In un sistema reale, restituiremmo un certificato X.509
     * firmato dalla BCE (Banca Centrale Europea).
     */
    private void processGetCertificate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = crypto.getPublicKey(buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * MUTUAL_AUTH — Autenticazione reciproca.
     *
     * FASE 1 del pagamento: prima di scambiarsi denaro,
     * i due chip devono verificare che l'altro sia autentico.
     *
     * ANALOGIA: Due persone che si mostrano i documenti d'identità
     * a vicenda prima di fare un affare importante.
     *
     * Protocollo semplificato:
     * 1. Chip A manda la sua chiave pubblica + un numero casuale
     * 2. Chip B verifica e risponde con la sua chiave + firma
     * 3. Entrambi ora sanno che l'altro è autentico
     */
    private void processMutualAuth(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        // In un'implementazione completa:
        // 1. Genera un challenge casuale
        // 2. Firma il challenge dell'altro chip
        // 3. Verifica la firma del challenge che abbiamo mandato

        // Per il prototipo: restituiamo la chiave pubblica come
        // "prova di identità"
        short len = crypto.getPublicKey(buffer, (short) 0);

        isAuthenticated = true;
        apdu.setOutgoingAndSend((short) 0, len);
    }
}
