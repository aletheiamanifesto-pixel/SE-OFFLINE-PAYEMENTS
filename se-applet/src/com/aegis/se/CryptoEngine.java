/**
 * AEGIS Offline Payment — Cryptographic Engine
 *
 * Handles ECDSA key generation, signing, verification and SHA-256
 * hashing inside the Secure Element.  All private-key material
 * NEVER leaves the SE.
 *
 * Curve:  secp256k1  (aligned with AEGIS on-chain identities)
 * Hash:   SHA-256
 * Sig:    ECDSA  (DER-encoded)
 *
 * @author AEGIS Protocol Team
 * @version 1.0.0
 */
package com.aegis.se;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class CryptoEngine {

    // ── Key pair ────────────────────────────────────────────────
    private KeyPair ecKeyPair;
    private ECPrivateKey privateKey;
    private ECPublicKey  publicKey;
    private boolean keysInitialized;

    // ── Signature / hash objects ────────────────────────────────
    private Signature ecdsaSigner;
    private Signature ecdsaVerifier;
    private MessageDigest sha256;

    // ── Scratch buffers (allocated once, reused) ────────────────
    private byte[] hashBuf;      // 32 bytes
    private byte[] sigBuf;       // 72 bytes max

    // ── secp256k1 domain parameters ─────────────────────────────
    // Field prime p
    private static final byte[] SECP256K1_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
    };
    // Coefficient a = 0
    private static final byte[] SECP256K1_A = {
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
    };
    // Coefficient b = 7
    private static final byte[] SECP256K1_B = {
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,7
    };
    // Generator point G (uncompressed, 65 bytes)
    private static final byte[] SECP256K1_G = {
        (byte)0x04,
        (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,
        (byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
        (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,
        (byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
        (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,
        (byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
        (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,
        (byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
        (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,
        (byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
        (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,
        (byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
        (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,
        (byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
        (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,
        (byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
    };
    // Order n
    private static final byte[] SECP256K1_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,
        (byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,
        (byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };
    // Cofactor h = 1
    private static final short SECP256K1_H = 1;

    /**
     * Allocate crypto primitives.  Called once during applet install.
     */
    public CryptoEngine() {
        sha256  = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hashBuf = JCSystem.makeTransientByteArray(Constants.HASH_LEN,
                    JCSystem.CLEAR_ON_DESELECT);
        sigBuf  = JCSystem.makeTransientByteArray(Constants.MAX_SIGNATURE_LEN,
                    JCSystem.CLEAR_ON_DESELECT);
        keysInitialized = false;
    }

    // ── Key management ──────────────────────────────────────────

    /**
     * Generate a fresh secp256k1 key pair on the SE.
     * Previous keys (if any) are destroyed.
     */
    public void generateKeyPair() {
        // Build domain-param-aware keys
        ecKeyPair   = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        privateKey  = (ECPrivateKey)  ecKeyPair.getPrivate();
        publicKey   = (ECPublicKey)   ecKeyPair.getPublic();

        // Set curve parameters
        privateKey.setFieldFP(SECP256K1_P, (short)0, (short)SECP256K1_P.length);
        privateKey.setA(SECP256K1_A, (short)0, (short)SECP256K1_A.length);
        privateKey.setB(SECP256K1_B, (short)0, (short)SECP256K1_B.length);
        privateKey.setG(SECP256K1_G, (short)0, (short)SECP256K1_G.length);
        privateKey.setR(SECP256K1_N, (short)0, (short)SECP256K1_N.length);
        privateKey.setK(SECP256K1_H);

        publicKey.setFieldFP(SECP256K1_P, (short)0, (short)SECP256K1_P.length);
        publicKey.setA(SECP256K1_A, (short)0, (short)SECP256K1_A.length);
        publicKey.setB(SECP256K1_B, (short)0, (short)SECP256K1_B.length);
        publicKey.setG(SECP256K1_G, (short)0, (short)SECP256K1_G.length);
        publicKey.setR(SECP256K1_N, (short)0, (short)SECP256K1_N.length);
        publicKey.setK(SECP256K1_H);

        ecKeyPair.genKeyPair();

        // Prepare signer / verifier
        ecdsaSigner   = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        ecdsaVerifier = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        ecdsaSigner.init(privateKey, Signature.MODE_SIGN);
        ecdsaVerifier.init(publicKey, Signature.MODE_VERIFY);

        keysInitialized = true;
    }

    /** @return true if a key pair has been generated */
    public boolean isInitialized() {
        return keysInitialized;
    }

    /**
     * Copy the compressed public key (33 bytes) into the destination buffer.
     *
     * @return number of bytes written
     */
    public short getPublicKey(byte[] dest, short destOff) {
        if (!keysInitialized)
            ISOException.throwIt(Constants.SW_KEYS_NOT_INIT);
        // getW returns uncompressed (04 || x || y) — 65 bytes
        byte[] tmp = JCSystem.makeTransientByteArray((short)65,
                       JCSystem.CLEAR_ON_DESELECT);
        short len = publicKey.getW(tmp, (short)0);
        // Compress: prefix 02 or 03 depending on y parity, then x (32 bytes)
        dest[destOff] = (byte)(((tmp[64] & 0x01) == 0) ? 0x02 : 0x03);
        Util.arrayCopyNonAtomic(tmp, (short)1, dest, (short)(destOff + 1), (short)32);
        return Constants.PUBKEY_COMPRESSED_LEN;
    }

    // ── Signing ─────────────────────────────────────────────────

    /**
     * Sign arbitrary data with the SE private key.
     *
     * @param data   buffer containing data to sign
     * @param off    offset
     * @param len    length
     * @param sigOut output buffer for the DER-encoded ECDSA signature
     * @param sigOff offset in sigOut
     * @return       length of signature written
     */
    public short sign(byte[] data, short off, short len,
                      byte[] sigOut, short sigOff) {
        if (!keysInitialized)
            ISOException.throwIt(Constants.SW_KEYS_NOT_INIT);
        return ecdsaSigner.sign(data, off, len, sigOut, sigOff);
    }

    // ── Verification ────────────────────────────────────────────

    /**
     * Verify an ECDSA signature against the SE's own public key.
     * (Used for self-tests; peer verification uses loadPeerKey.)
     */
    public boolean verify(byte[] data, short dataOff, short dataLen,
                          byte[] sig,  short sigOff,  short sigLen) {
        if (!keysInitialized)
            ISOException.throwIt(Constants.SW_KEYS_NOT_INIT);
        return ecdsaVerifier.verify(data, dataOff, dataLen, sig, sigOff, sigLen);
    }

    /**
     * Verify using an external (peer) public key provided as
     * uncompressed point (65 bytes).
     */
    public boolean verifyWithPeerKey(byte[] peerPubKey, short pkOff, short pkLen,
                                     byte[] data, short dataOff, short dataLen,
                                     byte[] sig,  short sigOff,  short sigLen) {
        ECPublicKey peerKey = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        peerKey.setFieldFP(SECP256K1_P, (short)0, (short)SECP256K1_P.length);
        peerKey.setA(SECP256K1_A, (short)0, (short)SECP256K1_A.length);
        peerKey.setB(SECP256K1_B, (short)0, (short)SECP256K1_B.length);
        peerKey.setG(SECP256K1_G, (short)0, (short)SECP256K1_G.length);
        peerKey.setR(SECP256K1_N, (short)0, (short)SECP256K1_N.length);
        peerKey.setK(SECP256K1_H);
        peerKey.setW(peerPubKey, pkOff, pkLen);

        Signature v = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        v.init(peerKey, Signature.MODE_VERIFY);
        return v.verify(data, dataOff, dataLen, sig, sigOff, sigLen);
    }

    // ── Hashing ─────────────────────────────────────────────────

    /**
     * Compute SHA-256 digest.
     *
     * @return 32 (always)
     */
    public short sha256(byte[] in, short inOff, short inLen,
                        byte[] out, short outOff) {
        return sha256.doFinal(in, inOff, inLen, out, outOff);
    }
}
