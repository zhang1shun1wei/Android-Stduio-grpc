package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.io.TeeInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;

public class ClientHello {
    private final ProtocolVersion version;
    private final byte[] random;
    private final byte[] sessionID;
    private final byte[] cookie;
    private final int[] cipherSuites;
    private final Hashtable extensions;
    private final int bindersSize;

    public ClientHello(ProtocolVersion version, byte[] random, byte[] sessionID, byte[] cookie, int[] cipherSuites, Hashtable extensions, int bindersSize) {
        this.version = version;
        this.random = random;
        this.sessionID = sessionID;
        this.cookie = cookie;
        this.cipherSuites = cipherSuites;
        this.extensions = extensions;
        this.bindersSize = bindersSize;
    }

    public int getBindersSize() {
        return this.bindersSize;
    }

    public int[] getCipherSuites() {
        return this.cipherSuites;
    }

    /** @deprecated */
    public ProtocolVersion getClientVersion() {
        return this.version;
    }

    public byte[] getCookie() {
        return this.cookie;
    }

    public Hashtable getExtensions() {
        return this.extensions;
    }

    public byte[] getRandom() {
        return this.random;
    }

    public byte[] getSessionID() {
        return this.sessionID;
    }

    public ProtocolVersion getVersion() {
        return this.version;
    }

    public void encode(TlsContext context, OutputStream output) throws IOException {
        if (this.bindersSize < 0) {
            throw new TlsFatalAlert((short)80);
        } else {
            TlsUtils.writeVersion(this.version, output);
            output.write(this.random);
            TlsUtils.writeOpaque8(this.sessionID, output);
            if (null != this.cookie) {
                TlsUtils.writeOpaque8(this.cookie, output);
            }

            TlsUtils.writeUint16ArrayWithUint16Length(this.cipherSuites, output);
            TlsUtils.writeUint8ArrayWithUint8Length(new short[]{0}, output);
            TlsProtocol.writeExtensions(output, this.extensions, this.bindersSize);
        }
    }

    public static ClientHello parse(ByteArrayInputStream messageInput, OutputStream dtlsOutput) throws TlsFatalAlert {
        try {
            return implParse(messageInput, dtlsOutput);
        } catch (TlsFatalAlert var3) {
            throw var3;
        } catch (IOException var4) {
            throw new TlsFatalAlert((short)50, var4);
        }
    }

    private static ClientHello implParse(ByteArrayInputStream messageInput, OutputStream dtlsOutput) throws IOException {
        InputStream input = messageInput;
        if (null != dtlsOutput) {
            input = new TeeInputStream(messageInput, dtlsOutput);
        }

        ProtocolVersion clientVersion = TlsUtils.readVersion((InputStream)input);
        byte[] random = TlsUtils.readFully(32, (InputStream)input);
        byte[] sessionID = TlsUtils.readOpaque8((InputStream)input, 0, 32);
        byte[] cookie = null;
        int cipher_suites_length;
        if (null != dtlsOutput) {
            cipher_suites_length = ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(clientVersion) ? 255 : 32;
            cookie = TlsUtils.readOpaque8(messageInput, 0, cipher_suites_length);
        }

        cipher_suites_length = TlsUtils.readUint16((InputStream)input);
        if (cipher_suites_length >= 2 && (cipher_suites_length & 1) == 0 && messageInput.available() >= cipher_suites_length) {
            int[] cipherSuites = TlsUtils.readUint16Array(cipher_suites_length / 2, (InputStream)input);
            short[] compressionMethods = TlsUtils.readUint8ArrayWithUint8Length((InputStream)input, 1);
            if (!Arrays.contains(compressionMethods, (short)0)) {
                throw new TlsFatalAlert((short)40);
            } else {
                Hashtable extensions = null;
                if (messageInput.available() > 0) {
                    byte[] extBytes = TlsUtils.readOpaque16((InputStream)input);
                    TlsProtocol.assertEmpty(messageInput);
                    extensions = TlsProtocol.readExtensionsDataClientHello(extBytes);
                }

                return new ClientHello(clientVersion, random, sessionID, cookie, cipherSuites, extensions, -1);
            }
        } else {
            throw new TlsFatalAlert((short)50);
        }
    }
}
