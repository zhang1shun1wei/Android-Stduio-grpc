package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;

public class ServerHello {
    private static final byte[] HELLO_RETRY_REQUEST_MAGIC = {-49, 33, -83, 116, -27, -102, 97, 17, -66, 29, -116, 2, 30, 101, -72, -111, -62, -94, 17, 22, 122, -69, -116, 94, 7, -98, 9, -30, -56, -88, 51, -100};
    private final int cipherSuite;
    private final Hashtable extensions;
    private final byte[] random;
    private final byte[] sessionID;
    private final ProtocolVersion version;

    public ServerHello(byte[] sessionID2, int cipherSuite2, Hashtable extensions2) {
        this(ProtocolVersion.TLSv12, Arrays.clone(HELLO_RETRY_REQUEST_MAGIC), sessionID2, cipherSuite2, extensions2);
    }

    public ServerHello(ProtocolVersion version2, byte[] random2, byte[] sessionID2, int cipherSuite2, Hashtable extensions2) {
        this.version = version2;
        this.random = random2;
        this.sessionID = sessionID2;
        this.cipherSuite = cipherSuite2;
        this.extensions = extensions2;
    }

    public int getCipherSuite() {
        return this.cipherSuite;
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

    public boolean isHelloRetryRequest() {
        return Arrays.areEqual(HELLO_RETRY_REQUEST_MAGIC, this.random);
    }

    public void encode(TlsContext context, OutputStream output) throws IOException {
        TlsUtils.writeVersion(this.version, output);
        output.write(this.random);
        TlsUtils.writeOpaque8(this.sessionID, output);
        TlsUtils.writeUint16(this.cipherSuite, output);
        TlsUtils.writeUint8((short) 0, output);
        TlsProtocol.writeExtensions(output, this.extensions);
    }

    public static ServerHello parse(ByteArrayInputStream input) throws IOException {
        ProtocolVersion version2 = TlsUtils.readVersion(input);
        byte[] random2 = TlsUtils.readFully(32, input);
        byte[] sessionID2 = TlsUtils.readOpaque8(input, 0, 32);
        int cipherSuite2 = TlsUtils.readUint16(input);
        if (TlsUtils.readUint8(input) == 0) {
            return new ServerHello(version2, random2, sessionID2, cipherSuite2, TlsProtocol.readExtensions(input));
        }
        throw new TlsFatalAlert((short) 47);
    }
}
