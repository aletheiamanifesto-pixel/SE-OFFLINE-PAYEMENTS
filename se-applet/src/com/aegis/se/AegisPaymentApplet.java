/**
 * AEGIS Offline Payment — Secure Element Applet
 *
 * Main Java Card applet that runs inside the Secure Element.
 * Dispatches incoming APDU commands to the appropriate handler.
 *
 * Supported operations:
 *   • GET_BALANCE       — query wallet balance
 *   • GET_COUNTER       — query monotonic tx counter
 *   • GET_PUBLIC_KEY    — export compressed public key (33 B)
 *   • INITIATE_PAYMENT  — debit + sign receipt
 *   • RECEIVE_PAYMENT   — verify receipt + credit
 *   • VERIFY_SIGNATURE  — standalone sig check
 *   • GET_LAST_RECEIPT  — retrieve last tx receipt
 *   • LOAD_BALANCE      — issuer loads funds (PIN required)
 *   • VERIFY_PIN        — unlock privileged commands
 *   • GENERATE_KEYS     — create fresh ECDSA key pair
 *   • GET_VERSION       — applet version info
 *
 * @author AEGIS Protocol Team
 * @version 1.0.0
 */
package com.aegis.se;

import javacard.framework.*;

public class AegisPaymentApplet extends Applet {

    // ── Sub-modules ─────────────────────────────────────────────
    private CryptoEngine        crypto;
    private TransactionManager  txManager;

    // ── PIN ─────────────────────────────────────────────────────
    private OwnerPIN pin;
    /** Default PIN: 000000 — must be changed on first use */
    private static final byte[] DEFAULT_PIN = {
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30   // ASCII "000000"
    };

    // ── Work buffers ────────────────────────────────────────────
    private byte[] tmpBuf;   // transient 256 bytes

    // ─────────────────────────────────────────────────────────────
    //  Install & lifecycle
    // ─────────────────────────────────────────────────────────────

    /**
     * Applet constructor — called once during install.
     *
     * @param bArray  install parameters
     * @param bOffset offset
     * @param bLength length
     */
    protected AegisPaymentApplet(byte[] bArray, short bOffset, byte bLength) {
        crypto    = new CryptoEngine();
        txManager = new TransactionManager(crypto);

        pin = new OwnerPIN(Constants.PIN_MAX_RETRIES, Constants.PIN_LENGTH);
        pin.update(DEFAULT_PIN, (short)0, Constants.PIN_LENGTH);

        tmpBuf = JCSystem.makeTransientByteArray((short)256,
                   JCSystem.CLEAR_ON_DESELECT);

        register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    /**
     * Standard Java Card install entry point.
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new AegisPaymentApplet(bArray, bOffset, bLength);
    }

    /**
     * Called when the applet is selected (e.g. after NFC tap).
     */
    public boolean select() {
        // Reset PIN validated status on each new selection
        pin.reset();
        return true;
    }

    /**
     * Called when the applet is deselected.
     */
    public void deselect() {
        pin.reset();
    }

    // ─────────────────────────────────────────────────────────────
    //  APDU dispatcher
    // ─────────────────────────────────────────────────────────────

    public void process(APDU apdu) {
        // Ignore SELECT APDU (handled by JCRE)
        if (selectingApplet()) return;

        byte[] buf = apdu.getBuffer();
        byte cla   = buf[ISO7816.OFFSET_CLA];
        byte ins   = buf[ISO7816.OFFSET_INS];

        if (cla != Constants.CLA_AEGIS)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        switch (ins) {
            case Constants.INS_GET_VERSION:
                processGetVersion(apdu);
                break;
            case Constants.INS_GET_BALANCE:
                processGetBalance(apdu);
                break;
            case Constants.INS_GET_COUNTER:
                processGetCounter(apdu);
                break;
            case Constants.INS_GET_PUBLIC_KEY:
                processGetPublicKey(apdu);
                break;
            case Constants.INS_INITIATE_PAYMENT:
                processInitiatePayment(apdu);
                break;
            case Constants.INS_RECEIVE_PAYMENT:
                processReceivePayment(apdu);
                break;
            case Constants.INS_GET_LAST_RECEIPT:
                processGetLastReceipt(apdu);
                break;
            case Constants.INS_LOAD_BALANCE:
                processLoadBalance(apdu);
                break;
            case Constants.INS_VERIFY_PIN:
                processVerifyPin(apdu);
                break;
            case Constants.INS_GENERATE_KEYS:
                processGenerateKeys(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  Command handlers
    // ─────────────────────────────────────────────────────────────

    /** INS 0x02 — GET_VERSION → 3 bytes (major, minor, patch) */
    private void processGetVersion(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        buf[0] = Constants.VERSION_MAJOR;
        buf[1] = Constants.VERSION_MINOR;
        buf[2] = Constants.VERSION_PATCH;
        apdu.setOutgoingAndSend((short)0, (short)3);
    }

    /** INS 0x10 — GET_BALANCE → 4 bytes (big-endian euro-cents) */
    private void processGetBalance(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        int bal = txManager.getBalance();
        buf[0] = (byte)((bal >> 24) & 0xFF);
        buf[1] = (byte)((bal >> 16) & 0xFF);
        buf[2] = (byte)((bal >>  8) & 0xFF);
        buf[3] = (byte)((bal)       & 0xFF);
        apdu.setOutgoingAndSend((short)0, (short)4);
    }

    /** INS 0x12 — GET_COUNTER → 4 bytes (big-endian) */
    private void processGetCounter(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        int cnt = txManager.getCounter();
        buf[0] = (byte)((cnt >> 24) & 0xFF);
        buf[1] = (byte)((cnt >> 16) & 0xFF);
        buf[2] = (byte)((cnt >>  8) & 0xFF);
        buf[3] = (byte)((cnt)       & 0xFF);
        apdu.setOutgoingAndSend((short)0, (short)4);
    }

    /** INS 0x14 — GET_PUBLIC_KEY → 33 bytes compressed key */
    private void processGetPublicKey(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = crypto.getPublicKey(buf, (short)0);
        apdu.setOutgoingAndSend((short)0, len);
    }

    /**
     * INS 0x20 — INITIATE_PAYMENT
     *
     * Data in:  [receiver_pubkey (33 B)] [amount (4 B)] [timestamp (8 B)]
     *           Total Lc = 45
     * Data out: signed receipt (83 + sig bytes)
     */
    private void processInitiatePayment(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc != 45)
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);

        short off = ISO7816.OFFSET_CDATA;
        // Receiver public key (33 bytes)
        short rkOff = off;
        off += Constants.PUBKEY_COMPRESSED_LEN;
        // Amount (4 bytes)
        int amount = ((buf[off] & 0xFF) << 24)
                   | ((buf[(short)(off+1)] & 0xFF) << 16)
                   | ((buf[(short)(off+2)] & 0xFF) <<  8)
                   | ((buf[(short)(off+3)] & 0xFF));
        off += 4;
        // Timestamp (8 bytes)
        short tsOff = off;

        // Build and sign receipt
        short receiptLen = txManager.initiatePayment(
            amount,
            buf, rkOff,
            buf, tsOff,
            tmpBuf, (short)0);

        // Copy receipt to APDU buffer and send
        Util.arrayCopyNonAtomic(tmpBuf, (short)0, buf, (short)0, receiptLen);
        apdu.setOutgoingAndSend((short)0, receiptLen);
    }

    /**
     * INS 0x22 — RECEIVE_PAYMENT
     *
     * Data in: [sender_pubkey_uncompressed (65 B)] [signed_receipt (var)]
     *          Total Lc ≥ 65 + 83 + 8 = 156
     */
    private void processReceivePayment(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < (short)156)
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);

        short off = ISO7816.OFFSET_CDATA;
        // Sender uncompressed public key (65 B)
        short spkOff = off;
        off += 65;
        // Remaining bytes = signed receipt
        short receiptLen = (short)(lc - 65);

        txManager.receivePayment(buf, off, receiptLen,
                                 buf, spkOff);
        // Success — SW 9000 sent automatically
    }

    /** INS 0x40 — GET_LAST_RECEIPT → receipt bytes or empty */
    private void processGetLastReceipt(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = txManager.getLastReceipt(buf, (short)0);
        if (len > 0)
            apdu.setOutgoingAndSend((short)0, len);
    }

    /**
     * INS 0x50 — LOAD_BALANCE (issuer only, requires PIN)
     *
     * Data in: [amount (4 B)]   Lc = 4
     */
    private void processLoadBalance(APDU apdu) {
        if (!pin.isValidated())
            ISOException.throwIt(Constants.SW_PIN_REQUIRED);

        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc != 4)
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);

        short off = ISO7816.OFFSET_CDATA;
        int amount = ((buf[off] & 0xFF) << 24)
                   | ((buf[(short)(off+1)] & 0xFF) << 16)
                   | ((buf[(short)(off+2)] & 0xFF) <<  8)
                   | ((buf[(short)(off+3)] & 0xFF));

        txManager.loadBalance(amount);
    }

    /**
     * INS 0x60 — VERIFY_PIN
     *
     * Data in: [pin (6 B)]   Lc = 6
     */
    private void processVerifyPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc != Constants.PIN_LENGTH)
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);

        if (!pin.check(buf, ISO7816.OFFSET_CDATA, (byte)lc)) {
            short retries = pin.getTriesRemaining();
            ISOException.throwIt((short)(Constants.SW_PIN_INCORRECT | retries));
        }
    }

    /** INS 0x70 — GENERATE_KEYS */
    private void processGenerateKeys(APDU apdu) {
        crypto.generateKeyPair();
        // Return the new public key
        processGetPublicKey(apdu);
    }
}
