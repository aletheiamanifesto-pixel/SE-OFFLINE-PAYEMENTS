package ecb.deuro.offline;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * CryptoManager — Gestione Crittografica sul Chip Sicuro
 * ═══════════════════════════════════════════════════════════════════
 *
 * ANALOGIA: IL NOTAIO DIGITALE
 * ────────────────────────────
 * Immagina un notaio che ha un timbro UNICO al mondo (chiave privata).
 * Quando firma un documento, chiunque può verificare che il timbro
 * è autentico usando il registro pubblico (chiave pubblica),
 * ma NESSUNO può falsificare quel timbro.
 *
 * Questo è esattamente ciò che fa la crittografia ECDSA:
 * - Chiave privata = il timbro segreto del notaio (MAI esce dal chip)
 * - Chiave pubblica = il registro pubblico per le verifiche
 * - Firma = il timbro apposto su ogni transazione
 *
 * PERCHÉ ECDSA secp256r1?
 * ──────────────────────
 * - È lo standard usato da Bitcoin, Ethereum e dall'Euro Digitale
 * - secp256r1 (P-256) è la curva raccomandata da NIST e BCE
 * - 128 bit di sicurezza: servirebbero miliardi di anni per forzarla
 * - Supportata nativamente dall'hardware dei Secure Element
 *
 * PERCHÉ SHA-256?
 * ──────────────
 * Prima di firmare, calcoliamo l'hash (impronta digitale) dei dati.
 * SHA-256 crea un'impronta di 32 byte da dati di qualsiasi dimensione.
 * È come prendere le impronte digitali di un documento: univoche
 * e impossibili da falsificare.
 */
public class CryptoManager {

    // ─────────────────────────────────────────────────────────
    // Coppia di chiavi ECDSA — il "timbro" e il "registro"
    // ─────────────────────────────────────────────────────────

    /** Chiave privata ECDSA — il timbro segreto (MAI esce dal chip!) */
    private ECPrivateKey privateKey;

    /** Chiave pubblica ECDSA — il registro pubblico per le verifiche */
    private ECPublicKey publicKey;

    /** Oggetto per la firma digitale */
    private Signature signatureEngine;

    /** Oggetto per il calcolo dell'hash SHA-256 */
    private MessageDigest sha256;

    /** Buffer temporaneo per operazioni crittografiche */
    private byte[] tempBuffer;

    /** Dimensione della chiave in byte (256 bit = 32 byte) */
    private static final short KEY_SIZE_BYTES = (short) 32;

    /** Dimensione della chiave pubblica non compressa (1 + 32 + 32 = 65 byte) */
    private static final short PUBLIC_KEY_LENGTH = (short) 65;

    /** Dimensione massima della firma ECDSA (tipicamente 70-72 byte DER) */
    private static final short MAX_SIGNATURE_LENGTH = (short) 80;

    /** Dimensione dell'hash SHA-256 */
    private static final short HASH_LENGTH = (short) 32;

    /**
     * Costruttore — Genera la coppia di chiavi e inizializza
     * gli engine crittografici.
     *
     * NOTA: La generazione delle chiavi avviene UNA SOLA VOLTA,
     * durante l'installazione dell'applet. Le chiavi sono poi
     * memorizzate in modo persistente nella memoria sicura.
     *
     * ANALOGIA: È come quando il notaio riceve il suo timbro
     * ufficiale il primo giorno di lavoro — da quel momento
     * in poi, usa SEMPRE lo stesso timbro.
     */
    public CryptoManager() {
        // Genera la coppia di chiavi ECDSA P-256
        KeyPair keyPair = new KeyPair(
            KeyPair.ALG_EC_FP,     // Curva su campo primo (Fp)
            KeyBuilder.LENGTH_EC_FP_256  // 256 bit = secp256r1
        );
        keyPair.genKeyPair();

        // Salva i riferimenti alle chiavi
        privateKey = (ECPrivateKey) keyPair.getPrivate();
        publicKey = (ECPublicKey) keyPair.getPublic();

        // Inizializza l'engine di firma ECDSA con SHA-256
        signatureEngine = Signature.getInstance(
            Signature.ALG_ECDSA_SHA_256,
            false  // false = non usa padding
        );

        // Inizializza l'engine SHA-256 per hashing generico
        sha256 = MessageDigest.getInstance(
            MessageDigest.ALG_SHA_256,
            false
        );

        // Buffer temporaneo per operazioni intermedie
        tempBuffer = JCSystem.makeTransientByteArray(
            (short) 128,
            JCSystem.CLEAR_ON_DESELECT
        );
    }

    /**
     * Firma digitale dei dati con la chiave privata.
     *
     * ANALOGIA: Il notaio legge il documento, calcola un codice
     * univoco (hash), e poi appone il suo timbro ufficiale (firma).
     *
     * @param data      i dati da firmare
     * @param dataOff   posizione iniziale nei dati
     * @param dataLen   lunghezza dei dati
     * @param sig       buffer dove scrivere la firma
     * @param sigOff    posizione nel buffer della firma
     * @return lunghezza della firma in byte
     */
    public short sign(byte[] data, short dataOff, short dataLen,
                      byte[] sig, short sigOff) {
        // Inizializza l'engine con la chiave privata
        signatureEngine.init(privateKey, Signature.MODE_SIGN);

        // Firma i dati (internamente: hash SHA-256 + firma ECDSA)
        return signatureEngine.sign(data, dataOff, dataLen, sig, sigOff);
    }

    /**
     * Verifica una firma digitale con una chiave pubblica.
     *
     * ANALOGIA: Chiunque può andare al registro pubblico
     * e verificare che il timbro su un documento sia autentico.
     *
     * @param data      i dati originali
     * @param dataOff   posizione nei dati
     * @param dataLen   lunghezza dei dati
     * @param sig       la firma da verificare
     * @param sigOff    posizione nella firma
     * @param sigLen    lunghezza della firma
     * @return true se la firma è valida
     */
    public boolean verify(byte[] data, short dataOff, short dataLen,
                          byte[] sig, short sigOff, short sigLen) {
        // Inizializza l'engine con la chiave pubblica
        signatureEngine.init(publicKey, Signature.MODE_VERIFY);

        // Verifica la firma
        return signatureEngine.verify(data, dataOff, dataLen,
                                       sig, sigOff, sigLen);
    }

    /**
     * Calcola l'hash SHA-256 dei dati.
     *
     * ANALOGIA: Prendere le "impronte digitali" di un documento.
     * Anche cambiando una sola virgola, l'impronta cambia totalmente.
     *
     * @param data    dati di input
     * @param offset  posizione iniziale
     * @param length  lunghezza dei dati
     * @param hash    buffer per l'hash risultante
     * @param hashOff posizione nel buffer hash
     * @return lunghezza dell'hash (sempre 32 byte)
     */
    public short computeHash(byte[] data, short offset, short length,
                             byte[] hash, short hashOff) {
        return sha256.doFinal(data, offset, length, hash, hashOff);
    }

    /**
     * Esporta la chiave pubblica (il "certificato" semplificato).
     *
     * In un sistema reale, qui restituiremmo un certificato X.509
     * firmato da una CA (Autorità di Certificazione, come la BCE).
     * Per semplicità, restituiamo solo la chiave pubblica grezza.
     *
     * @param dest   buffer di destinazione
     * @param offset posizione nel buffer
     * @return numero di byte scritti (65 per chiave non compressa)
     */
    public short getPublicKey(byte[] dest, short offset) {
        return publicKey.getW(dest, offset);
    }

    /**
     * Restituisce la lunghezza della chiave pubblica.
     */
    public short getPublicKeyLength() {
        return PUBLIC_KEY_LENGTH;
    }

    /**
     * Restituisce la lunghezza massima di una firma.
     */
    public short getMaxSignatureLength() {
        return MAX_SIGNATURE_LENGTH;
    }
}
