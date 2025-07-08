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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.ProtocolFamily;
import java.net.SocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

public class ClamdClient {

    private static final byte[] PING_CMD = "zPING\000".getBytes(UTF_8);
    private static final byte[] PONG_REPLY = "PONG\000".getBytes(UTF_8);
    private static final byte[] VERSION_CMD = "zVERSION\000".getBytes(UTF_8);
    private static final byte[] VERSIONCOMMANDS_CMD = "zVERSIONCOMMANDS\000".getBytes(UTF_8);
    private static final byte[] RELOAD_CMD = "zRELOAD\000".getBytes(UTF_8);
    private static final byte[] RELOADING_REPLY = "RELOADING\000".getBytes(UTF_8);
    private static final byte[] INSTREAM_CMD = "zINSTREAM\000".getBytes(UTF_8);
    private static final byte[] SHUTDOWN_CMD = "zSHUTDOWN\000".getBytes(UTF_8);

    private final ProtocolFamily protocolFamily;
    private final SocketAddress socketAddress;
    private int connectTimeout = 2000;
    private int baseTimeout = 2000;
    private int scanTimeout = 120_000;

    public ClamdClient(String host, int port) {
        InetSocketAddress isa = new InetSocketAddress(host, port);
        if (isa.getAddress() instanceof Inet4Address) {
            protocolFamily = StandardProtocolFamily.INET;
        } else {
            protocolFamily = StandardProtocolFamily.INET6;
        }
        socketAddress = isa;
    }

    public ClamdClient(String unixDomainSocket) {
        protocolFamily = StandardProtocolFamily.UNIX;
        socketAddress = UnixDomainSocketAddress.of(unixDomainSocket);
    }

    public int getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public int getBaseTimeout() {
        return baseTimeout;
    }

    public void setBaseTimeout(int baseTimeout) {
        this.baseTimeout = baseTimeout;
    }

    public int getScanTimeout() {
        return scanTimeout;
    }

    public void setScanTimeout(int scanTimeout) {
        this.scanTimeout = scanTimeout;
    }

    public void checkConnection() throws IOException {
        runWithConnection((selectionKey) -> {
            writeToChannel(selectionKey, ByteBuffer.wrap(PING_CMD), baseTimeout);
            byte[] result = readFromChannel(selectionKey, baseTimeout);
            if (!Arrays.equals(PONG_REPLY, result)) {
                throw new IOException("Expected PONG, but got: " + new String(result, UTF_8));
            }
            return Void.class;
        });
    }

    public void reload() throws IOException {
        runWithConnection((selectionKey) -> {
            writeToChannel(selectionKey, ByteBuffer.wrap(RELOAD_CMD), baseTimeout);
            byte[] result = readFromChannel(selectionKey, baseTimeout);
            if (!Arrays.equals(RELOADING_REPLY, result)) {
                throw new IOException("Expected RELOADING, but got: " + new String(result, UTF_8));
            }
            return Void.class;
        });
    }

    public void shutdown() throws IOException {
        runWithConnection((selectionKey) -> {
            writeToChannel(selectionKey, ByteBuffer.wrap(SHUTDOWN_CMD), baseTimeout);
            return Void.class;
        });
    }

    public String getVersion() throws IOException {
        return runWithConnection((selectionKey) -> {
            writeToChannel(selectionKey, ByteBuffer.wrap(VERSION_CMD), baseTimeout);
            byte[] result = readFromChannel(selectionKey, baseTimeout);
            return new String(result, UTF_8);
        });
    }

    public VersionCommands getVersionsCommands() throws IOException {
        return runWithConnection((selectionKey) -> {
            writeToChannel(selectionKey, ByteBuffer.wrap(VERSIONCOMMANDS_CMD), baseTimeout);
            byte[] result = readFromChannel(selectionKey, baseTimeout);
            String versionString = new String(result, UTF_8);
            String[] splittedString = versionString.split("\\| COMMANDS:");
            if (splittedString.length < 2) {
                return new VersionCommands(splittedString[0]);
            } else {
                List<String> commands = Arrays
                        .stream(splittedString[1].split("\\s"))
                        .filter(s -> !s.isBlank())
                        .map(s -> s.trim())
                        .collect(Collectors.toUnmodifiableList());
                return new VersionCommands(splittedString[0], commands);
            }
        });
    }

    public ScanResult scanStream(byte[] input) throws IOException {
        return scanStream(new ByteArrayInputStream(input));
    }

    public ScanResult scanStream(InputStream is) throws IOException {
        return runWithConnection((selectionKey) -> {
            writeToChannel(selectionKey, ByteBuffer.wrap(INSTREAM_CMD), baseTimeout);

            byte[] buffer = new byte[4096 + 4];
            ByteBuffer bb = ByteBuffer.wrap(buffer);

            try {
                while (true) {
                    int read = is.read(buffer, 4, 4096);
                    if (read < 0) {
                        break;
                    }
                    bb.putInt(0, read);
                    bb.position(0);
                    bb.limit(4 + read);
                    writeToChannel(selectionKey, bb, baseTimeout);
                }

                bb.position(0);
                bb.limit(4);
                bb.putInt(0, 0);
                writeToChannel(selectionKey, bb, baseTimeout);
            } catch (IOException ex) {
            }

            String result = new String(readFromChannel(selectionKey, scanTimeout), UTF_8);

            if (result.endsWith(" FOUND")) {
                // Assume that the last ": " sequence is the separator between
                // the path and the virusname i.e. "<PATH>: <VIRUSNAME> <STATUS>"
                int lastColon = result.lastIndexOf(": ");
                String virusName = result;
                if(lastColon >= 0 && (lastColon + 2 < (result.length() - 6))) {
                    virusName = result.substring(lastColon + 2, result.length() - 6).trim();
                }
                return new ScanResult(ScanState.FOUND, result, virusName);
            } else if (result.endsWith(" ERROR")) {
                return new ScanResult(ScanState.ERROR, result, null);
            } else if (result.endsWith(" OK")) {
                return new ScanResult(ScanState.OK, result, null);
            } else {
                return new ScanResult(ScanState.ERROR, "Unexpected scanning result: " + result, null);
            }
        });
    }

    private SelectionKey establishConnection(final SocketChannel sc, final Selector selector) throws IOException {
        sc.configureBlocking(false);
        sc.connect(socketAddress);
        SelectionKey selectionKey = sc.register(selector, 0);
        selectionKey.interestOps(SelectionKey.OP_CONNECT);
        selectionKey.selector().select(connectTimeout);
        sc.finishConnect();
        return selectionKey;
    }

    private byte[] readFromChannel(SelectionKey selectionKey, long timeout_milli) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        long start = System.nanoTime();
        ByteBuffer bb = ByteBuffer.allocate(4096);
        selectionKey.interestOps(SelectionKey.OP_READ);
        waitReadableWithTimeout(selectionKey, start, timeout_milli);
        while (((SocketChannel) selectionKey.channel()).read(bb) >= 0) {
            bb.flip();
            if (bb.limit() > 0 && bb.get(bb.limit() - 1) == 0) {
                if (bb.limit() > 1) {
                    baos.write(bb.array(), bb.position(), bb.limit() - bb.position() - 1);
                }
                break;
            } else {
                baos.write(bb.array(), bb.position(), bb.limit() - bb.position());
            }
            waitReadableWithTimeout(selectionKey, start, timeout_milli);
            if (isTimeout(start, timeout_milli)) {
                throw new IOException("Timeout while reading");
            }
        }
        return baos.toByteArray();
    }

    private void waitReadableWithTimeout(SelectionKey selectionKey, long start, long timeout_milli) throws IOException {
        selectionKey.selector().select(timeout_milli / 10);
        while (!isTimeout(start, timeout_milli)) {
            if (!selectionKey.isReadable()) {
                selectionKey.selector().select(timeout_milli / 10);
            } else {
                break;
            }
        }
    }

    private void waitWriteableWithTimeout(SelectionKey selectionKey, long start, long timeout_milli) throws IOException {
        selectionKey.selector().select(timeout_milli / 10);
        while (!isTimeout(start, timeout_milli)) {
            if (!selectionKey.isWritable()) {
                selectionKey.selector().select(timeout_milli / 10);
            } else {
                break;
            }
        }
    }

    private void writeToChannel(SelectionKey selectionKey, ByteBuffer bb, long timeout_milli) throws IOException {
        long start = System.nanoTime();
        selectionKey.interestOps(SelectionKey.OP_WRITE);
        waitWriteableWithTimeout(selectionKey, start, timeout_milli);
        while (((SocketChannel) selectionKey.channel()).write(bb) >= 0) {
            if (bb.position() >= bb.limit()) {
                break;
            }
            waitWriteableWithTimeout(selectionKey, start, timeout_milli);
            if (isTimeout(start, timeout_milli)) {
                throw new IOException("Timeout while writing");
            }
        }
    }

    private static boolean isTimeout(long start, long timeout_milli) {
        long timeout_nano = timeout_milli * 1000L * 1000L;
        Long now = System.nanoTime();
        Long timeoutComp = now - timeout_nano;
        boolean isTimout = Long.compare(timeoutComp, start) > 0;
        return isTimout;
    }

    private interface IOThrowingFunction<T> {

        T apply(SelectionKey sk) throws IOException;
    }

    private <T> T runWithConnection(IOThrowingFunction<T> f) throws IOException {
        try (SocketChannel sc = SocketChannel.open(protocolFamily);
                Selector selector = Selector.open()) {
            SelectionKey selectionKey = establishConnection(sc, selector);

            return f.apply(selectionKey);
        }
    }
}
