/*
 * Copyright 2025 Matthias Bläsing
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.doppelhelix.lib.clamdclient;

import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;

import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ClamdClientTest {

    @Test
    public void testParseResultLine() throws IOException {
        assertScanResult(ScanState.OK, null, "stream: OK");
        assertScanResult(ScanState.FOUND, "Win.Test.EICAR_HDB-1", "stream: Win.Test.EICAR_HDB-1 FOUND");
        assertScanResult(ScanState.ERROR, null, "home/matthias/img1000: File path check failure: No such file or directory. ERROR");
    }

    private static void assertScanResult(ScanState expectedState, String expectedVirus, String resultLine) {
        ScanResult sr = ClamdClient.parseResultLine(resultLine);
        assertEquals(expectedState, sr.state());
        assertEquals(expectedVirus, sr.virus());
    }

    @Test
    public void testParseCommands() throws IOException {
        VersionCommands vc = ClamdClient.parseVersionsCommands(
                "ClamAV 1.4.3/27691/Sun Jul  6 10:34:52 2025| COMMANDS: SCAN QUIT RELOAD PING CONTSCAN VERSIONCOMMANDS VERSION END SHUTDOWN MULTISCAN FILDES STATS IDSESSION INSTREAM DETSTATSCLEAR DETSTATS ALLMATCHSCAN"
        );
        List<String> commands = asList(
                "SCAN", "QUIT", "RELOAD", "PING", "CONTSCAN", "VERSIONCOMMANDS",
                "VERSION", "END", "SHUTDOWN", "MULTISCAN", "FILDES", "STATS",
                "IDSESSION", "INSTREAM", "DETSTATSCLEAR", "DETSTATS",
                "ALLMATCHSCAN");

        assertEquals("ClamAV 1.4.3/27691/Sun Jul  6 10:34:52 2025", vc.version());
        assertEquals(commands, vc.commands());
    }


}
