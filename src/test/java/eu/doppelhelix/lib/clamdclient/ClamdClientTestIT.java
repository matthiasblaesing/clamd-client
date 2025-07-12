package eu.doppelhelix.lib.clamdclient;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ClamdClientTestIT {

    private static final ClamdClient TCP_CLIENT = new ClamdClient("localhost", 3310);
    private static final ClamdClient UNIX_CLIENT = new ClamdClient("/tmp/clamd.ctl");

    private static Stream<ClamdClient> provideClients() {
        return Stream.of(TCP_CLIENT, UNIX_CLIENT);
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    public void testCheckConnection(ClamdClient client) throws Exception {
        client.checkConnection();
    }

    @Test
    @SuppressWarnings("ThrowableResultIgnored")
    public void testCheckConnectionTCPWrongPort() throws Exception {
        Assertions.assertThrows(
                IOException.class,
                () -> {
                    ClamdClient client = new ClamdClient("localhost", 2712);
                    client.checkConnection();
                });
    }

    @Test
    @SuppressWarnings("ThrowableResultIgnored")
    public void testCheckConnectionUnixDomainSocketNotExisting() throws Exception {
        Assertions.assertThrows(
                IOException.class,
                () -> {
                    ClamdClient client = new ClamdClient("/tmp/dummy");
                    client.checkConnection();
                });
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    @SuppressWarnings({"ThrowableResultIgnored", "SleepWhileInLoop"})
    public void testReload(ClamdClient client) throws Exception {
        Files.write(Path.of("/tmp/clamd.log"), new byte[0], StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        assertFalse(
                Files.readString(Path.of("/tmp/clamd.log"), StandardCharsets.UTF_8)
                        .contains("Database correctly reloaded")
        );
        client.reload();
        boolean reloaded = false;
        for (int i = 0; i < 120; i++) {
            reloaded = Files.readString(Path.of("/tmp/clamd.log"), StandardCharsets.UTF_8)
                    .contains("Database correctly reloaded");
            if (reloaded) {
                break;
            }
            Thread.sleep(500);
        }
        assertTrue(reloaded);
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    @SuppressWarnings("ThrowableResultIgnored")
    public void testVersionCommandToVersionCommand(ClamdClient client) throws Exception {
        String version = client.getVersion();
        VersionCommands vc = client.getVersionsCommands();
        assertEquals(version, vc.version());
        assertNotNull(vc.commands());
        assertTrue(vc.commands().contains("INSTREAM"));
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    public void testStreamScanningFoundByteArray(ClamdClient client) throws Exception {
        // Split, so that "other scanning software does not get trigger happy
        byte[] eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*")
                .getBytes(StandardCharsets.US_ASCII);
        ScanResult sr = client.scanStream(eicar);
        assertEquals(ScanState.FOUND, sr.state());
        assertEquals("Win.Test.EICAR_HDB-1", sr.virus());
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    public void testStreamScanningNotFoundByteArray(ClamdClient client) throws Exception {
        byte[] dummyData = "DummyData".getBytes(StandardCharsets.US_ASCII);
        ScanResult sr = client.scanStream(dummyData);
        assertEquals(ScanState.OK, sr.state());
        assertNull(sr.virus());
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    public void testMultiPackageScanByteArray(ClamdClient client) throws Exception {
        // Multi-Package in this case means, that the content does not fit into
        // a single package send by ClamdClient#scanStream(InputStream)
        byte[] dummyData = new byte[1 * 1000 * 1000];
        ScanResult sr = client.scanStream(dummyData);
        assertEquals(ScanState.OK, sr.state());
        assertNull(sr.virus());
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    public void testLargeStreamByteArray(ClamdClient client) throws Exception {
        byte[] dummyData = new byte[15 * 1000 * 1000];
        ScanResult sr = client.scanStream(dummyData);
        assertEquals(ScanState.ERROR, sr.state());
        assertNull(sr.virus());
        assertTrue(sr.resultString().contains("size limit exceeded"));
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    public void testStreamScanningFoundStream(ClamdClient client) throws Exception {
        // Split, so that "other scanning software does not get trigger happy
        byte[] eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*")
                .getBytes(StandardCharsets.US_ASCII);
        ScanResult sr = client.scanStream(new ByteArrayInputStream(eicar));
        assertEquals(ScanState.FOUND, sr.state());
        assertEquals("Win.Test.EICAR_HDB-1", sr.virus());
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    public void testStreamScanningNotFoundStream(ClamdClient client) throws Exception {
        byte[] dummyData = "DummyData".getBytes(StandardCharsets.US_ASCII);
        ScanResult sr = client.scanStream(new ByteArrayInputStream(dummyData));
        assertEquals(ScanState.OK, sr.state());
        assertNull(sr.virus());
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    public void testMultiPackageScanStream(ClamdClient client) throws Exception {
        // Multi-Package in this case means, that the content does not fit into
        // a single package send by ClamdClient#scanStream(InputStream)
        byte[] dummyData = new byte[1 * 1000 * 1000];
        ScanResult sr = client.scanStream(new ByteArrayInputStream(dummyData));
        assertEquals(ScanState.OK, sr.state());
        assertNull(sr.virus());
    }

    @ParameterizedTest
    @MethodSource("provideClients")
    public void testLargeStreamStream(ClamdClient client) throws Exception {
        byte[] dummyData = new byte[15 * 1000 * 1000];
        ScanResult sr = client.scanStream(new ByteArrayInputStream(dummyData));
        assertEquals(ScanState.ERROR, sr.state());
        assertNull(sr.virus());
        assertTrue(sr.resultString().contains("size limit exceeded"));
    }

}
