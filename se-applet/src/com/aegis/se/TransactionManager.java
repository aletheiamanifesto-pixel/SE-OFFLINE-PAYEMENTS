/**
 * AEGIS Offline Payment — Transaction Manager
 *
 * Manages wallet state (balance, counter) and builds/validates
 * transaction receipts.  All state mutations are atomic (wrapped
 * in JCSystem transactions so that a power-loss mid-NFC won't
 * corrupt the wallet).
 *
 * Receipt binary layout (v1):
 *   [0]      version       (1 byte  = 0x01)
 *   [1..33]  sender pubkey (33 bytes, compressed)
 *   [34..66] receiver pubkey (33 bytes, compressed)
 *   [67..70] amount        (4 bytes, big-endian, euro-cents)
 *   [71..74] counter       (4 bytes, big-endian)
 *   [75..82] timestamp     (8 bytes, big-endian, millis)
 *   [83..N]  ECDSA signature over bytes [0..82]
 *
 * @author AEGIS Protocol Team
 * @version 1.0.0
 */
package com.aegis.se;

import javacard.framework.*;

public class TransactionManager {

    // ── Persistent wallet state ─────────────────────────────────
    /** Balance in euro-cents, stored as 4 bytes big-endian */
    private byte[] balance;          // 4 bytes
    /** Monotonic counter, stored as 4 bytes big-endian */
    private byte[] counter;          // 4 bytes
    /** Last receipt blob (up to 155 bytes: 83 header + 72 sig) */
    private byte[] lastReceipt;
    private short  lastReceiptLen;

    // ── Scratch (transient) ─────────────────────────────────────
    private byte[] receiptBuf;       // transient work buffer

    private CryptoEngine crypto;

    /**
     * Allocate persistent + transient storage.
     */
    public TransactionManager(CryptoEngine crypto) {
        this.crypto = crypto;
        balance       = new byte[4];
        counter       = new byte[4];
        lastReceipt   = new byte[160];
        lastReceiptLen = 0;
        receiptBuf    = JCSystem.makeTransientByteArray((short)160,
                          JCSystem.CLEAR_ON_DESELECT);
    }

    // ── Balance helpers ─────────────────────────────────────────

    /** Read balance as a 32-bit signed int (euro-cents). */
    public int getBalance() {
        return ((balance[0] & 0xFF) << 24)
             | ((balance[1] & 0xFF) << 16)
             | ((balance[2] & 0xFF) <<  8)
             | ((balance[3] & 0xFF));
    }

    /** Store balance (big-endian). */
    private void setBalance(int val) {
        balance[0] = (byte)((val >> 24) & 0xFF);
        balance[1] = (byte)((val >> 16) & 0xFF);
        balance[2] = (byte)((val >>  8) & 0xFF);
        balance[3] = (byte)((val)       & 0xFF);
    }

    /** Read counter as 32-bit unsigned (fits in int for values < 2^31). */
    public int getCounter() {
        return ((counter[0] & 0xFF) << 24)
             | ((counter[1] & 0xFF) << 16)
             | ((counter[2] & 0xFF) <<  8)
             | ((counter[3] & 0xFF));
    }

    private void incrementCounter() {
        // Big-endian increment with carry
        for (short i = 3; i >= 0; i--) {
            short val = (short)((counter[i] & 0xFF) + 1);
            counter[i] = (byte)(val & 0xFF);
            if (val <= 0xFF) return;  // no carry
        }
        // Overflow — should never happen with 4 billion tx limit
        ISOException.throwIt(Constants.SW_COUNTER_OVERFLOW);
    }

    // ── Payment operations ──────────────────────────────────────

    /**
     * Initiate a DEBIT (sender side).
     *
     * @param amount        euro-cents (must be > 0 and ≤ MAX_SINGLE_PAYMENT)
     * @param receiverPubKey compressed public key of the receiver (33 bytes)
     * @param rkOff         offset
     * @param timestamp     8-byte big-endian timestamp from host
     * @param tsOff         offset
     * @param outBuf        buffer to write the signed receipt
     * @param outOff        offset
     * @return              length of the receipt (header + signature)
     */
    public short initiatePayment(int amount,
                                 byte[] receiverPubKey, short rkOff,
                                 byte[] timestamp, short tsOff,
                                 byte[] outBuf, short outOff) {
        // Validate amount
        if (amount <= 0 || amount > Constants.MAX_SINGLE_PAYMENT)
            ISOException.throwIt(Constants.SW_INVALID_AMOUNT);
        // Check funds
        int bal = getBalance();
        if (bal < amount)
            ISOException.throwIt(Constants.SW_INSUFFICIENT_FUNDS);

        // Build receipt header in scratch buffer
        short off = 0;
        receiptBuf[off++] = Constants.RECEIPT_VERSION;
        // Sender pubkey (this SE)
        off += crypto.getPublicKey(receiptBuf, off);
        // Receiver pubkey
        Util.arrayCopyNonAtomic(receiverPubKey, rkOff,
                                receiptBuf, off,
                                Constants.PUBKEY_COMPRESSED_LEN);
        off += Constants.PUBKEY_COMPRESSED_LEN;
        // Amount (4 bytes BE)
        receiptBuf[off++] = (byte)((amount >> 24) & 0xFF);
        receiptBuf[off++] = (byte)((amount >> 16) & 0xFF);
        receiptBuf[off++] = (byte)((amount >>  8) & 0xFF);
        receiptBuf[off++] = (byte)((amount)       & 0xFF);
        // Counter (4 bytes BE) — use NEXT counter value
        int nextCnt = getCounter() + 1;
        receiptBuf[off++] = (byte)((nextCnt >> 24) & 0xFF);
        receiptBuf[off++] = (byte)((nextCnt >> 16) & 0xFF);
        receiptBuf[off++] = (byte)((nextCnt >>  8) & 0xFF);
        receiptBuf[off++] = (byte)((nextCnt)       & 0xFF);
        // Timestamp (8 bytes)
        Util.arrayCopyNonAtomic(timestamp, tsOff,
                                receiptBuf, off, (short)8);
        off += 8;

        // Sign the header
        short sigLen = crypto.sign(receiptBuf, (short)0, off,
                                   receiptBuf, off);
        short totalLen = (short)(off + sigLen);

        // ── Atomic state update ────────────────────────────────
        JCSystem.beginTransaction();
        setBalance(bal - amount);
        incrementCounter();
        Util.arrayCopyNonAtomic(receiptBuf, (short)0,
                                lastReceipt, (short)0, totalLen);
        lastReceiptLen = totalLen;
        JCSystem.commitTransaction();

        // Copy to output
        Util.arrayCopyNonAtomic(receiptBuf, (short)0,
                                outBuf, outOff, totalLen);
        return totalLen;
    }

    /**
     * Receive a CREDIT (receiver side).
     *
     * Validates the sender's receipt, verifies the signature,
     * then atomically credits the balance and increments the counter.
     *
     * @param receipt       full signed receipt from the sender
     * @param rOff          offset
     * @param rLen          total length (header + sig)
     * @param senderPubKeyUncompressed  65-byte uncompressed sender key (for verify)
     * @param spkOff        offset
     */
    public void receivePayment(byte[] receipt, short rOff, short rLen,
                               byte[] senderPubKeyUncompressed,
                               short spkOff) {
        // Basic length check
        if (rLen < (short)(Constants.RECEIPT_MIN_LEN + 8))
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);

        short headerLen = Constants.RECEIPT_MIN_LEN;
        short sigOff    = (short)(rOff + headerLen);
        short sigLen    = (short)(rLen - headerLen);

        // Verify ECDSA signature
        boolean valid = crypto.verifyWithPeerKey(
            senderPubKeyUncompressed, spkOff, (short)65,
            receipt, rOff, headerLen,
            receipt, sigOff, sigLen);
        if (!valid)
            ISOException.throwIt(Constants.SW_SIGNATURE_INVALID);

        // Extract amount (4 bytes at offset 67)
        int amount = ((receipt[(short)(rOff + Constants.RECEIPT_AMOUNT_OFF)] & 0xFF) << 24)
                   | ((receipt[(short)(rOff + Constants.RECEIPT_AMOUNT_OFF + 1)] & 0xFF) << 16)
                   | ((receipt[(short)(rOff + Constants.RECEIPT_AMOUNT_OFF + 2)] & 0xFF) <<  8)
                   | ((receipt[(short)(rOff + Constants.RECEIPT_AMOUNT_OFF + 3)] & 0xFF));

        if (amount <= 0 || amount > Constants.MAX_SINGLE_PAYMENT)
            ISOException.throwIt(Constants.SW_INVALID_AMOUNT);

        int newBal = getBalance() + amount;
        if (newBal > Constants.MAX_BALANCE)
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_MET);

        // ── Atomic credit ──────────────────────────────────────
        JCSystem.beginTransaction();
        setBalance(newBal);
        incrementCounter();
        Util.arrayCopyNonAtomic(receipt, rOff,
                                lastReceipt, (short)0, rLen);
        lastReceiptLen = rLen;
        JCSystem.commitTransaction();
    }

    /**
     * Administrative balance load (issuer-only, after PIN verification).
     *
     * @param amount euro-cents to add
     */
    public void loadBalance(int amount) {
        if (amount <= 0)
            ISOException.throwIt(Constants.SW_INVALID_AMOUNT);
        int newBal = getBalance() + amount;
        if (newBal > Constants.MAX_BALANCE)
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_MET);

        JCSystem.beginTransaction();
        setBalance(newBal);
        JCSystem.commitTransaction();
    }

    /**
     * Copy last receipt into output buffer.
     *
     * @return length of receipt, or 0 if no receipt stored
     */
    public short getLastReceipt(byte[] out, short outOff) {
        if (lastReceiptLen == 0) return 0;
        Util.arrayCopyNonAtomic(lastReceipt, (short)0,
                                out, outOff, lastReceiptLen);
        return lastReceiptLen;
    }
}
