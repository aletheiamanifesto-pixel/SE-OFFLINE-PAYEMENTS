package com.aegis.se;

import javacard.framework.JCSystem;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Gestore crittografia ECDSA P-256 per l'applet OfflineDigitalEuro.
 *
 * Si occupa di:
 *  - Generazione della coppia di chiavi ECDSA P-256 all'installazione
 *  - Firma di transazioni con la chiave privata locale
 *  - Verifica di firme ECDSA di altri partecipanti
 *  - Hashing SHA-256 dei dati di transazione
 *
 * Le chiavi sono generate DENTRO il chip con un True Random Number Generator
 * hardware. La chiave privata non esce mai dal chip.
 */
public class CryptoManager {

    // ─── Parametri curva P-256 (secp256r1) ────────────────────────────────────

    private static final byte[] P256_A = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFC
    };

    private static final byte[] P256_B = {
        (byte)0x5A,(byte)0xC6,(byte)0x35,(byte)0xD8,(byte)0xAA,(byte)0x3A,(byte)0x93,(byte)0xE7,
        (byte)0xB3,(byte)0xEB,(byte)0xBD,(byte)0x55,(byte)0x76,(byte)0x98,(byte)0x86,(byte)0xBC,
        (byte)0x65,(byte)0x1D,(byte)0x06,(byte)0xB0,(byte)0xCC,(byte)0x53,(byte)0xB0,(byte)0xF6,
        (byte)0x3B,(byte)0xCE,(byte)0x3C,(byte)0x3E,(byte)0x27,(byte)0xD2,(byte)0x60,(byte)0x4B
    };

    private static final byte[] P256_G = {
        (byte)0x04,
        (byte)0x6B,(byte)0x17,(byte)0xD1,(byte)0xF2,(byte)0xE1,(byte)0x2C,(byte)0x42,(byte)0x47,
        (byte)0xF8,(byte)0xBC,(byte)0xE6,(byte)0xE5,(byte)0x63,(byte)0xA4,(byte)0x40,(byte)0xF2,
        (byte)0x77,(byte)0x03,(byte)0x7D,(byte)0x81,(byte)0x2D,(byte)0xEB,(byte)0x33,(byte)0xA0,
        (byte)0xF4,(byte)0xA1,(byte)0x39,(byte)0x45,(byte)0xD8,(byte)0x98,(byte)0xC2,(byte)0x96,
        (byte)0x4F,(byte)0xE3,(byte)0x42,(byte)0xE2,(byte)0xFE,(byte)0x1A,(byte)0x7F,(byte)0x9B,
        (byte)0x8E,(byte)0xE7,(byte)0xEB,(byte)0x4A,(byte)0x7C,(byte)0x0F,(byte)0x9E,(byte)0x16,
        (byte)0x2B,(byte)0xCE,(byte)0x33,(byte)0x57,(byte)0x6B,(byte)0x31,(byte)0x5E,(byte)0xCE,
        (byte)0xCB,(byte)0xB6,(byte)0x40,(byte)0x68,(byte)0x37,(byte)0xBF,(byte)0x51,(byte)0xF5
    };

    private static final byte[] P256_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xBC,(byte)0xE6,(byte)0xFA,(byte)0xAD,(byte)0xA7,(byte)0x17,(byte)0x9E,(byte)0x84,
        (byte)0xF3,(byte)0xB9,(byte)0xCA,(byte)0xC2,(byte)0xFC,(byte)0x63,(byte)0x25,(byte)0x51
    };

    private static final byte[] P256_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF
    };

    // ─── Oggetti crittografici ─────────────────────────────────────────────────

    private final KeyPair keyPair;
    private final ECPrivateKey privateKey;
    private final ECPublicKey publicKey;
    private final Signature signerECDSA;
    private final Signature verifierECDSA;
    private final MessageDigest sha256;

    /** Buffer temporaneo per operazioni intermedie (in RAM transiente). */
    private final byte[] tmpBuffer;
    private static final short TMP_BUFFER_SIZE = 256;

    /**
     * Inizializza il gestore crittografico e genera la coppia di chiavi.
     * Chiamato una sola volta all'installazione dell'applet.
     */
    public CryptoManager() {
        // Genera coppia di chiavi ECDSA P-256 con TRNG hardware
        keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        ECPublicKey tmpPub   = (ECPublicKey)  KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,  KeyBuilder.LENGTH_EC_FP_256, false);
        ECPrivateKey tmpPriv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);

        // Imposta i parametri della curva P-256
        setP256Params(tmpPub);
        setP256Params(tmpPriv);
        keyPair.genKeyPair();

        privateKey = (ECPrivateKey) keyPair.getPrivate();
        publicKey  = (ECPublicKey)  keyPair.getPublic();

        // Oggetti per firma e verifica ECDSA con SHA-256
        signerECDSA   = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        verifierECDSA = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        // Buffer temporaneo in RAM (veloce, si cancella a ogni sessione)
        tmpBuffer = JCSystem.makeTransientByteArray(TMP_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Imposta i parametri della curva P-256 su una chiave EC.
     */
    private void setP256Params(ECKey key) {
        key.setA(P256_A, (short) 0, (short) P256_A.length);
        key.setB(P256_B, (short) 0, (short) P256_B.length);
        key.setG(P256_G, (short) 0, (short) P256_G.length);
        key.setN(P256_N, (short) 0, (short) P256_N.length);
        key.setFieldFP(P256_P, (short) 0, (short) P256_P.length);
    }

    /**
     * Firma un buffer di dati con la chiave privata di questo chip.
     *
     * @param data   dati da firmare
     * @param offset offset iniziale nei dati
     * @param length lunghezza dei dati
     * @param sig    buffer di output per la firma
     * @param sigOff offset nel buffer di output
     * @return lunghezza della firma prodotta (DER, max 72 byte)
     */
    public short sign(byte[] data, short offset, short length, byte[] sig, short sigOff) {
        signerECDSA.init(privateKey, Signature.MODE_SIGN);
        return signerECDSA.sign(data, offset, length, sig, sigOff);
    }

    /**
     * Verifica una firma ECDSA usando la chiave pubblica fornita.
     *
     * @param data      dati originali
     * @param dataOff   offset nei dati
     * @param dataLen   lunghezza dati
     * @param pubKeyRaw chiave pubblica in formato non compresso (65 byte: 0x04 || X || Y)
     * @param pkOff     offset nella chiave pubblica
     * @param sig       firma da verificare
     * @param sigOff    offset nella firma
     * @param sigLen    lunghezza firma
     * @return true se la firma è valida
     */
    public boolean verify(byte[] data,      short dataOff, short dataLen,
                          byte[] pubKeyRaw, short pkOff,
                          byte[] sig,       short sigOff,  short sigLen) {
        // Costruisce una ECPublicKey temporanea dalla chiave raw ricevuta
        ECPublicKey remotePubKey = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        setP256Params(remotePubKey);
        remotePubKey.setW(pubKeyRaw, pkOff, APDUConstants.SIZE_PUBLIC_KEY);

        verifierECDSA.init(remotePubKey, Signature.MODE_VERIFY);
        return verifierECDSA.verify(data, dataOff, dataLen, sig, sigOff, sigLen);
    }

    /**
     * Copia la chiave pubblica di questo chip nel buffer fornito.
     *
     * @param dest   buffer di destinazione
     * @param offset offset nel buffer
     * @return numero di byte copiati (65)
     */
    public short getPublicKey(byte[] dest, short offset) {
        return publicKey.getW(dest, offset);
    }

    /**
     * Calcola SHA-256 di un buffer.
     *
     * @param data   dati in input
     * @param offset offset iniziale
     * @param length lunghezza
     * @param out    buffer di output (32 byte)
     * @param outOff offset nel buffer output
     */
    public void hash(byte[] data, short offset, short length, byte[] out, short outOff) {
        sha256.reset();
        sha256.doFinal(data, offset, length, out, outOff);
    }
}
