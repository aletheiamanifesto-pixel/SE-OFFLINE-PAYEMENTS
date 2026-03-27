/**
 * AEGIS Offline Payment — Secure Element Constants
 *
 * Defines all APDU instruction codes, status words, and protocol
 * constants used by the Secure Element applet.
 *
 * APDU Format (ISO 7816-4):
 *   CLA | INS | P1 | P2 | Lc | Data | Le
 *
 * @author AEGIS Protocol Team
 * @version 1.0.0
 */
package com.aegis.se;

public final class Constants {

    private Constants() { }

    // ── AID (Application Identifier) ────────────────────────────
    /** RID (5 bytes) + PIX (up to 11 bytes) */
    public static final byte[] APPLET_AID = {
        (byte) 0xA0, 0x00, 0x00, 0x08, 0x47,   // RID
        0x41, 0x45, 0x47, 0x49, 0x53, 0x01      // PIX: "AEGIS" + version
    };

    // ── CLA ─────────────────────────────────────────────────────
    public static final byte CLA_AEGIS = (byte) 0x80;

    // ── INS (Instruction codes) ─────────────────────────────────
    /** Query current balance */
    public static final byte INS_GET_BALANCE       = (byte) 0x10;
    /** Query monotonic transaction counter */
    public static final byte INS_GET_COUNTER       = (byte) 0x12;
    /** Retrieve wallet public key (compressed, 33 bytes) */
    public static final byte INS_GET_PUBLIC_KEY    = (byte) 0x14;
    /** Initiate an outgoing payment (debit) */
    public static final byte INS_INITIATE_PAYMENT  = (byte) 0x20;
    /** Receive an incoming payment (credit) */
    public static final byte INS_RECEIVE_PAYMENT   = (byte) 0x22;
    /** Verify a transaction signature */
    public static final byte INS_VERIFY_SIGNATURE  = (byte) 0x30;
    /** Get the last transaction receipt */
    public static final byte INS_GET_LAST_RECEIPT  = (byte) 0x40;
    /** Administrative: load balance (issuer only, requires PIN) */
    public static final byte INS_LOAD_BALANCE      = (byte) 0x50;
    /** Verify PIN before privileged operations */
    public static final byte INS_VERIFY_PIN        = (byte) 0x60;
    /** Generate a fresh key pair on the SE */
    public static final byte INS_GENERATE_KEYS     = (byte) 0x70;
    /** Get SE applet version info */
    public static final byte INS_GET_VERSION       = (byte) 0x02;

    // ── Status Words ────────────────────────────────────────────
    public static final short SW_OK                  = (short) 0x9000;
    public static final short SW_INSUFFICIENT_FUNDS  = (short) 0x6985;
    public static final short SW_INVALID_AMOUNT      = (short) 0x6A80;
    public static final short SW_PIN_REQUIRED        = (short) 0x6982;
    public static final short SW_PIN_INCORRECT       = (short) 0x63C0; // C0 + retries
    public static final short SW_COUNTER_OVERFLOW    = (short) 0x6A84;
    public static final short SW_SIGNATURE_INVALID   = (short) 0x6988;
    public static final short SW_KEYS_NOT_INIT       = (short) 0x6985;
    public static final short SW_WRONG_LENGTH        = (short) 0x6700;
    public static final short SW_CONDITIONS_NOT_MET  = (short) 0x6985;

    // ── Limits ──────────────────────────────────────────────────
    /** Maximum single payment in euro-cents */
    public static final int MAX_SINGLE_PAYMENT     = 500_00;  // 500.00 €
    /** Maximum wallet balance in euro-cents */
    public static final long MAX_BALANCE           = 3000_00; // 3 000.00 €
    /** Maximum value of the monotonic counter */
    public static final long MAX_COUNTER           = 0xFFFFFFFFL;
    /** PIN length (digits) */
    public static final byte PIN_LENGTH            = 6;
    /** Maximum PIN retries before lock-out */
    public static final byte PIN_MAX_RETRIES       = 3;

    // ── Crypto ──────────────────────────────────────────────────
    /** ECDSA curve: secp256k1 (same as AEGIS on-chain) */
    public static final String CURVE_NAME          = "secp256k1";
    /** Length of a compressed public key */
    public static final byte PUBKEY_COMPRESSED_LEN = 33;
    /** Max length of a DER-encoded ECDSA signature */
    public static final byte MAX_SIGNATURE_LEN     = 72;
    /** SHA-256 digest length */
    public static final byte HASH_LEN              = 32;

    // ── Receipt fields (byte offsets inside a receipt blob) ─────
    public static final byte RECEIPT_VERSION       = 0x01;
    public static final byte RECEIPT_HEADER_LEN    = 1;
    public static final byte RECEIPT_SENDER_OFF    = 1;
    public static final byte RECEIPT_RECEIVER_OFF  = 34;  // 1 + 33
    public static final byte RECEIPT_AMOUNT_OFF    = 67;  // 34 + 33
    public static final byte RECEIPT_COUNTER_OFF   = 71;  // 67 + 4
    public static final byte RECEIPT_TIMESTAMP_OFF = 75;  // 71 + 4
    public static final byte RECEIPT_SIG_OFF       = 83;  // 75 + 8
    /** Minimum receipt size (without signature) */
    public static final byte RECEIPT_MIN_LEN       = 83;

    // ── Version ─────────────────────────────────────────────────
    public static final byte VERSION_MAJOR = 1;
    public static final byte VERSION_MINOR = 0;
    public static final byte VERSION_PATCH = 0;
}
