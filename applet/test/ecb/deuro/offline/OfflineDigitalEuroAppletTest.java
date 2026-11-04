package ecb.deuro.offline;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test dell'applet nel simulatore jCardSim: il chip gira dentro la JVM
 * e riceve gli stessi comandi APDU che riceverebbe via NFC.
 */
class OfflineDigitalEuroAppletTest {

    /** AID con cui l'applet viene installata (vedi build.gradle). */
    private static final AID AID_APPLET = AIDUtil.create("F0414547495300");

    private static final int CLA = 0x80;
    private static final int SW_OK = 0x9000;
    private static final int SW_RIFIUTATO = 0x6985;

    private CardSimulator chip;

    @BeforeEach
    void installaApplet() {
        chip = new CardSimulator();
        chip.installApplet(AID_APPLET, OfflineDigitalEuroApplet.class);
        chip.selectApplet(AID_APPLET);
    }

    // ─── Helper APDU ───────────────────────────────────────────

    private ResponseAPDU invia(byte ins, byte[] dati) {
        CommandAPDU cmd = dati == null
            ? new CommandAPDU(CLA, ins, 0x00, 0x00, 256)
            : new CommandAPDU(CLA, ins, 0x00, 0x00, dati);
        return chip.transmitCommand(cmd);
    }

    /** Importo in centesimi su 4 byte big-endian, come si aspetta l'applet. */
    private static byte[] importo(int centesimi) {
        return new byte[] {
            (byte) (centesimi >>> 24), (byte) (centesimi >>> 16),
            (byte) (centesimi >>> 8), (byte) centesimi
        };
    }

    private int saldo() {
        ResponseAPDU r = invia(APDUConstants.INS_GET_BALANCE, null);
        assertEquals(SW_OK, r.getSW(), "GET_BALANCE deve riuscire");
        byte[] d = r.getData();
        assertEquals(4, d.length, "il saldo è su 4 byte");
        return ((d[0] & 0xFF) << 24) | ((d[1] & 0xFF) << 16) | ((d[2] & 0xFF) << 8) | (d[3] & 0xFF);
    }

    private byte[] contatore() {
        ResponseAPDU r = invia(APDUConstants.INS_GET_COUNTER, null);
        assertEquals(SW_OK, r.getSW(), "GET_COUNTER deve riuscire");
        return r.getData();
    }

    private void ricarica(int centesimi) {
        assertEquals(SW_OK, invia(APDUConstants.INS_CREDIT, importo(centesimi)).getSW(),
            "la ricarica deve riuscire");
    }

    private int paga(int centesimi) {
        return invia(APDUConstants.INS_DEBIT, importo(centesimi)).getSW();
    }

    // ─── I quattro test ────────────────────────────────────────

    @Test
    void saldo_parteDaZeroEcresceConLaRicarica() {
        assertEquals(0, saldo());

        ricarica(100_00);

        assertEquals(100_00, saldo());
    }

    @Test
    void pagamentoValido_scalaIlSaldoEavanzaIlContatore() {
        ricarica(100_00);

        assertEquals(SW_OK, paga(3_50), "un caffè da 3,50 € deve passare");

        assertEquals(96_50, saldo());
        assertArrayEquals(new byte[] {0, 0, 0, 1}, contatore());
    }

    @Test
    void pagamentoOltreIlPlafond_vieneRifiutatoSenzaToccareNulla() {
        ricarica(320_00);

        // Oltre il limite per singola operazione, anche se il saldo basterebbe
        assertEquals(SW_RIFIUTATO, paga(WalletState.DEFAULT_MAX_TX_LIMIT + 1));
        // Oltre il saldo disponibile
        ricarica(0_01);
        assertEquals(SW_OK, paga(300_00));
        assertEquals(SW_RIFIUTATO, paga(20_02));

        assertEquals(20_01, saldo(), "i pagamenti rifiutati non scalano nulla");
        assertArrayEquals(new byte[] {0, 0, 0, 1}, contatore(),
            "i pagamenti rifiutati non consumano un valore del contatore");
    }

    @Test
    void riusoDelContatore_ogniPagamentoHaUnValoreNuovo() {
        ricarica(50_00);

        assertEquals(SW_OK, paga(1_00));
        byte[] primo = contatore();
        assertEquals(SW_RIFIUTATO, paga(100_00), "pagamento rifiutato in mezzo");
        assertEquals(SW_OK, paga(1_00));
        byte[] secondo = contatore();

        assertArrayEquals(new byte[] {0, 0, 0, 1}, primo);
        assertArrayEquals(new byte[] {0, 0, 0, 2}, secondo,
            "il contatore non si ripete e non salta: ogni pagamento ha il suo valore");

        // Il contatore è monotòno anche dopo una nuova selezione dell'applet
        chip.selectApplet(AID_APPLET);
        assertArrayEquals(secondo, contatore());
        assertEquals(SW_OK, paga(1_00));
        assertArrayEquals(new byte[] {0, 0, 0, 3}, contatore());
    }
}
