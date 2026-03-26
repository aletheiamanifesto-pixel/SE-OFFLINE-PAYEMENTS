package com.aegis.se;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Applet principale: OfflineDigitalEuro.
 *
 * Implementa un portafoglio di euro digitali che può eseguire pagamenti
 * offline peer-to-peer tramite NFC, senza necessità di connessione internet.
 *
 * Flusso pagamento (Alice → Bob):
 *  1. Bob invia INITIATE_PAYMENT (importo + chiave_pub_bob)
 *  2. Alice firma e restituisce la transazione
 *  3. Bob verifica e accredita con PROCESS_PAYMENT
 *  4. Bob invia CONFIRM_PAYMENT ad Alice
 *  5. Alice deduce il saldo
 *
 * AID: A0 00 00 08 48 41 45 47 01 00
 */
public class OfflineDigitalEuroApplet extends Applet {

    // ─── Componenti ───────────────────────────────────────────────────────────

    private final WalletState   wallet;
    private final CryptoManager crypto;

    // ─── Buffer transiente per la transazione in corso ────────────────────────

    /**
     * Buffer RAM (transiente) per i dati della transazione corrente.
     * Layout:
     *   [0..7]   = importo corrente (8 byte, centesimi big-endian)
     *   [8..72]  = chiave pubblica controparte (65 byte)
     *   [73..144]= firma ECDSA della controparte (max 72 byte)
     *   [145]    = lunghezza firma effettiva (1 byte)
     *   [146..149]= contatore controparte al momento del pagamento (4 byte)
     */
    private static final short TX_BUF_AMOUNT    = 0;
    private static final short TX_BUF_PUBKEY    = 8;
    private static final short TX_BUF_SIG       = 73;
    private static final short TX_BUF_SIGLEN    = 145;
    private static final short TX_BUF_PEER_CNT  = 146;
    private static final short TX_BUFFER_TOTAL  = 150;

    private final byte[] txBuffer;

    // ─── Buffer APDU di lavoro ────────────────────────────────────────────────

    private static final short WORK_BUFFER_SIZE = 256;
    private final byte[] workBuffer;

    // ─── Installazione ────────────────────────────────────────────────────────

    /**
     * Punto di ingresso per l'installazione dell'applet nel chip.
     * Chiamato una sola volta da GlobalPlatform durante il deploy.
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new OfflineDigitalEuroApplet().register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    /**
     * Costruttore privato: inizializza tutti i componenti.
     */
    private OfflineDigitalEuroApplet() {
        wallet     = new WalletState();
        crypto     = new CryptoManager();
        txBuffer   = JCSystem.makeTransientByteArray(TX_BUFFER_TOTAL,  JCSystem.CLEAR_ON_DESELECT);
        workBuffer = JCSystem.makeTransientByteArray(WORK_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }

    // ─── Dispatch APDU ────────────────────────────────────────────────────────

    /**
     * Punto di ingresso per ogni comando APDU ricevuto.
     */
    @Override
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        // Ignora il comando SELECT (gestito dal framework)
        if (selectingApplet()) {
            return;
        }

        // Verifica CLA
        if (buf[ISO7816.OFFSET_CLA] != APDUConstants.CLA_AEGIS) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Dispatch per INS
        switch (buf[ISO7816.OFFSET_INS]) {
            case APDUConstants.INS_GET_BALANCE:
                processGetBalance(apdu);
                break;
            case APDUConstants.INS_GET_PUBLIC_KEY:
                processGetPublicKey(apdu);
                break;
            case APDUConstants.INS_INITIATE_PAYMENT:
                processInitiatePayment(apdu);
                break;
            case APDUConstants.INS_PROCESS_PAYMENT:
                processProcessPayment(apdu);
                break;
            case APDUConstants.INS_CONFIRM_PAYMENT:
                processConfirmPayment(apdu);
                break;
            case APDUConstants.INS_GET_COUNTER:
                processGetCounter(apdu);
                break;
            case APDUConstants.INS_GET_TRANSACTION_LOG:
                processGetTransactionLog(apdu);
                break;
            case APDUConstants.INS_LOAD_FUNDS:
                processLoadFunds(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // ─── GET_BALANCE ──────────────────────────────────────────────────────────

    /** Restituisce il saldo corrente in centesimi (8 byte big-endian). */
    private void processGetBalance(APDU apdu) {
        wallet.copyBalanceTo(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, APDUConstants.SIZE_BALANCE);
    }

    // ─── GET_PUBLIC_KEY ───────────────────────────────────────────────────────

    /** Restituisce la chiave pubblica ECDSA (65 byte non compressa). */
    private void processGetPublicKey(APDU apdu) {
        short len = crypto.getPublicKey(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    // ─── INITIATE_PAYMENT ─────────────────────────────────────────────────────

    /**
     * Bob → Alice: avvia un pagamento.
     *
     * Input DATA (77 byte):
     *   [0..7]  importo in centesimi (uint64 big-endian)
     *   [8..72] chiave pubblica Bob (65 byte)
     *   [73..76] contatore Bob (uint32 big-endian)
     *
     * Output DATA (141 byte):
     *   [0..64]   chiave pubblica Alice (65 byte)
     *   [65..68]  contatore Alice attuale (4 byte)
     *   [69..140] firma ECDSA Alice del payload (max 72 byte)
     */
    private void processInitiatePayment(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc   = apdu.setIncomingAndReceive();

        // Verifica lunghezza input minima
        short expectedLc = (short) (APDUConstants.SIZE_BALANCE
                                  + APDUConstants.SIZE_PUBLIC_KEY
                                  + APDUConstants.SIZE_COUNTER);
        if (lc < expectedLc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Estrai importo
        long amountCents = bytesToLong(buf, ISO7816.OFFSET_CDATA);

        // Validazione importo
        if (amountCents <= 0) {
            ISOException.throwIt(APDUConstants.SW_INVALID_AMOUNT);
        }

        // Validazione saldo
        if (!wallet.hasSufficientFunds(amountCents)) {
            ISOException.throwIt(APDUConstants.SW_INSUFFICIENT_FUNDS);
        }

        // Validazione limite offline
        if (!wallet.isWithinOfflineLimit(amountCents)) {
            ISOException.throwIt(APDUConstants.SW_OFFLINE_LIMIT_EXCEEDED);
        }

        // Salva dati transazione nel buffer transiente
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA,
                                txBuffer, TX_BUF_AMOUNT, APDUConstants.SIZE_BALANCE);

        short pkBobOffset = (short) (ISO7816.OFFSET_CDATA + APDUConstants.SIZE_BALANCE);
        Util.arrayCopyNonAtomic(buf, pkBobOffset,
                                txBuffer, TX_BUF_PUBKEY, APDUConstants.SIZE_PUBLIC_KEY);

        short cntBobOffset = (short) (pkBobOffset + APDUConstants.SIZE_PUBLIC_KEY);
        Util.arrayCopyNonAtomic(buf, cntBobOffset,
                                txBuffer, TX_BUF_PEER_CNT, APDUConstants.SIZE_COUNTER);

        // Costruisci il payload da firmare:
        // importo (8B) + pubkey_alice (65B) + cnt_alice (4B) + pubkey_bob (65B) + cnt_bob (4B)
        short payloadLen = buildSigningPayload(workBuffer, (short) 0,
                                               amountCents,
                                               buf, pkBobOffset,           // pubkey bob
                                               buf, cntBobOffset);         // cnt bob

        // Firma il payload
        short sigLen = crypto.sign(workBuffer, (short) 0, payloadLen,
                                   workBuffer, (short) (WORK_BUFFER_SIZE / 2));
        txBuffer[TX_BUF_SIGLEN] = (byte) sigLen;

        // Costruisci risposta: pubkey_alice (65B) + cnt_alice (4B) + firma (sigLen B)
        byte[] outBuf = apdu.getBuffer();
        short  outOff = 0;

        // Chiave pubblica Alice
        short pubKeyLen = crypto.getPublicKey(outBuf, outOff);
        outOff += pubKeyLen;

        // Contatore Alice
        wallet.copyCounterTo(outBuf, outOff);
        outOff += APDUConstants.SIZE_COUNTER;

        // Firma
        Util.arrayCopyNonAtomic(workBuffer, (short) (WORK_BUFFER_SIZE / 2),
                                outBuf, outOff, sigLen);
        outOff += sigLen;

        apdu.setOutgoingAndSend((short) 0, outOff);
    }

    // ─── PROCESS_PAYMENT ──────────────────────────────────────────────────────

    /**
     * Alice → Bob: verifica la transazione firmata e accredita il saldo Bob.
     *
     * Input DATA:
     *   [0..7]   importo (8 byte)
     *   [8..72]  chiave pubblica Alice (65 byte)
     *   [73..76] contatore Alice (4 byte)
     *   [77..N]  firma ECDSA Alice
     *
     * Output DATA (8 byte): nuovo saldo Bob
     */
    private void processProcessPayment(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc   = apdu.setIncomingAndReceive();

        short minLc = (short) (APDUConstants.SIZE_BALANCE
                              + APDUConstants.SIZE_PUBLIC_KEY
                              + APDUConstants.SIZE_COUNTER + 1);
        if (lc < minLc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short off = ISO7816.OFFSET_CDATA;

        long amountCents    = bytesToLong(buf, off);
        off += APDUConstants.SIZE_BALANCE;

        short pkAliceOffset = off;
        off += APDUConstants.SIZE_PUBLIC_KEY;

        short cntAliceOffset = off;
        off += APDUConstants.SIZE_COUNTER;

        short sigOffset = off;
        short sigLen    = (short) (lc - (short)(sigOffset - ISO7816.OFFSET_CDATA));

        // Verifica contatore Alice (anti-replay)
        if (!wallet.isValidIncomingCounter(buf, cntAliceOffset)) {
            ISOException.throwIt(APDUConstants.SW_INVALID_COUNTER);
        }

        // Ricostruisci il payload che Alice ha firmato
        // importo (8B) + pubkey_alice (65B) + cnt_alice (4B) + pubkey_bob_this (65B) + cnt_bob_this (4B)
        short myPkLen   = crypto.getPublicKey(workBuffer, (short) 0);
        wallet.copyCounterTo(workBuffer, myPkLen);
        // payload = amount + pubkey_alice + cnt_alice + pubkey_this + cnt_this
        short payloadLen = buildSigningPayloadFull(
            workBuffer, (short) (WORK_BUFFER_SIZE / 2),
            amountCents,
            buf, pkAliceOffset,
            buf, cntAliceOffset,
            workBuffer, (short) 0,       // pubkey_this (già in workBuffer[0..64])
            workBuffer, myPkLen          // cnt_this
        );

        // Verifica firma ECDSA di Alice
        boolean valid = crypto.verify(
            workBuffer, (short) (WORK_BUFFER_SIZE / 2), payloadLen,
            buf, pkAliceOffset,
            buf, sigOffset, sigLen
        );
        if (!valid) {
            ISOException.throwIt(APDUConstants.SW_INVALID_SIGNATURE);
        }

        // Accredita il saldo di Bob
        wallet.credit(amountCents);
        wallet.incrementCounter();

        // Registra nel log
        wallet.logTransaction(amountCents, wallet.getCounterValue(), buf, pkAliceOffset);

        // Risposta: nuovo saldo (8 byte)
        wallet.copyBalanceTo(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, APDUConstants.SIZE_BALANCE);
    }

    // ─── CONFIRM_PAYMENT ──────────────────────────────────────────────────────

    /**
     * Bob → Alice: conferma ricezione. Alice aggiorna il proprio saldo.
     *
     * Input DATA (8 byte): importo da debitare (deve corrispondere al txBuffer)
     * Output DATA (8 byte): nuovo saldo Alice
     */
    private void processConfirmPayment(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        // Leggi l'importo dalla transazione in corso
        long amountCents = bytesToLong(txBuffer, TX_BUF_AMOUNT);

        if (amountCents == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Deduce il saldo di Alice e aggiorna il contatore
        wallet.debit(amountCents);
        wallet.incrementCounter();

        // Registra nel log
        wallet.logTransaction(amountCents, wallet.getCounterValue(),
                              txBuffer, TX_BUF_PUBKEY);

        // Azzera il txBuffer (transazione completata)
        Util.arrayFillNonAtomic(txBuffer, (short) 0, TX_BUFFER_TOTAL, (byte) 0);

        // Risposta: nuovo saldo Alice
        wallet.copyBalanceTo(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, APDUConstants.SIZE_BALANCE);
    }

    // ─── GET_COUNTER ──────────────────────────────────────────────────────────

    /** Restituisce il contatore corrente (4 byte big-endian). */
    private void processGetCounter(APDU apdu) {
        wallet.copyCounterTo(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, APDUConstants.SIZE_COUNTER);
    }

    // ─── GET_TRANSACTION_LOG ──────────────────────────────────────────────────

    /** Restituisce un record del log (P1 = indice, 0 = più recente). */
    private void processGetTransactionLog(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short  index = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);

        short len = wallet.getTransactionLog(index, apdu.getBuffer(), (short) 0);
        if (len < 0) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        apdu.setOutgoingAndSend((short) 0, len);
    }

    // ─── LOAD_FUNDS ───────────────────────────────────────────────────────────

    /**
     * Carica fondi nel portafoglio (richiede firma della CA).
     * In questa versione è semplificato: verifica solo la firma della CA.
     *
     * Input DATA (8 byte + firma): importo (8B) + firma_CA
     */
    private void processLoadFunds(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc   = apdu.setIncomingAndReceive();

        if (lc < APDUConstants.SIZE_BALANCE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        long amountCents = bytesToLong(buf, ISO7816.OFFSET_CDATA);
        if (amountCents <= 0) {
            ISOException.throwIt(APDUConstants.SW_INVALID_AMOUNT);
        }

        // TODO: verifica firma CA (richiede chiave pubblica CA nel chip)
        // Per ora accetta il caricamento diretto (solo per sviluppo/test)

        wallet.credit(amountCents);
        wallet.resetOfflineSpent();

        wallet.copyBalanceTo(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, APDUConstants.SIZE_BALANCE);
    }

    // ─── Helper ───────────────────────────────────────────────────────────────

    /**
     * Costruisce il payload da firmare per INITIATE_PAYMENT.
     * Payload = amount(8B) + pubkey_alice(65B) + cnt_alice(4B) + pubkey_bob(65B) + cnt_bob(4B)
     */
    private short buildSigningPayload(byte[] out, short outOff,
                                      long amountCents,
                                      byte[] pkBob,  short pkBobOff,
                                      byte[] cntBob, short cntBobOff) {
        short start = outOff;

        // Importo
        longToBytes(amountCents, out, outOff);
        outOff += APDUConstants.SIZE_BALANCE;

        // Chiave pubblica Alice
        short pkLen = crypto.getPublicKey(out, outOff);
        outOff += pkLen;

        // Contatore Alice
        wallet.copyCounterTo(out, outOff);
        outOff += APDUConstants.SIZE_COUNTER;

        // Chiave pubblica Bob
        Util.arrayCopyNonAtomic(pkBob, pkBobOff, out, outOff, APDUConstants.SIZE_PUBLIC_KEY);
        outOff += APDUConstants.SIZE_PUBLIC_KEY;

        // Contatore Bob
        Util.arrayCopyNonAtomic(cntBob, cntBobOff, out, outOff, APDUConstants.SIZE_COUNTER);
        outOff += APDUConstants.SIZE_COUNTER;

        return (short) (outOff - start);
    }

    /**
     * Variante completa di buildSigningPayload con tutti i parametri espliciti.
     */
    private short buildSigningPayloadFull(byte[] out,    short outOff,
                                          long amountCents,
                                          byte[] pkA,   short pkAOff,
                                          byte[] cntA,  short cntAOff,
                                          byte[] pkB,   short pkBOff,
                                          byte[] cntB,  short cntBOff) {
        short start = outOff;

        longToBytes(amountCents, out, outOff);
        outOff += APDUConstants.SIZE_BALANCE;

        Util.arrayCopyNonAtomic(pkA,  pkAOff,  out, outOff, APDUConstants.SIZE_PUBLIC_KEY);
        outOff += APDUConstants.SIZE_PUBLIC_KEY;

        Util.arrayCopyNonAtomic(cntA, cntAOff, out, outOff, APDUConstants.SIZE_COUNTER);
        outOff += APDUConstants.SIZE_COUNTER;

        Util.arrayCopyNonAtomic(pkB,  pkBOff,  out, outOff, APDUConstants.SIZE_PUBLIC_KEY);
        outOff += APDUConstants.SIZE_PUBLIC_KEY;

        Util.arrayCopyNonAtomic(cntB, cntBOff, out, outOff, APDUConstants.SIZE_COUNTER);
        outOff += APDUConstants.SIZE_COUNTER;

        return (short) (outOff - start);
    }

    private static long bytesToLong(byte[] buf, short off) {
        return ((long) (buf[off]              & 0xFF) << 56)
             | ((long) (buf[(short)(off + 1)] & 0xFF) << 48)
             | ((long) (buf[(short)(off + 2)] & 0xFF) << 40)
             | ((long) (buf[(short)(off + 3)] & 0xFF) << 32)
             | ((long) (buf[(short)(off + 4)] & 0xFF) << 24)
             | ((long) (buf[(short)(off + 5)] & 0xFF) << 16)
             | ((long) (buf[(short)(off + 6)] & 0xFF) <<  8)
             | ((long) (buf[(short)(off + 7)] & 0xFF));
    }

    private static void longToBytes(long v, byte[] buf, short off) {
        buf[off]              = (byte) ((v >> 56) & 0xFF);
        buf[(short)(off + 1)] = (byte) ((v >> 48) & 0xFF);
        buf[(short)(off + 2)] = (byte) ((v >> 40) & 0xFF);
        buf[(short)(off + 3)] = (byte) ((v >> 32) & 0xFF);
        buf[(short)(off + 4)] = (byte) ((v >> 24) & 0xFF);
        buf[(short)(off + 5)] = (byte) ((v >> 16) & 0xFF);
        buf[(short)(off + 6)] = (byte) ((v >>  8) & 0xFF);
        buf[(short)(off + 7)] = (byte) ( v         & 0xFF);
    }
}
