package com.mi.car.jsse.easysec.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/* access modifiers changed from: package-private */
public class HandshakeMessageOutput extends ByteArrayOutputStream {
    static int getLength(int bodyLength) {
        return bodyLength + 4;
    }

    static void send(TlsProtocol protocol, short handshakeType, byte[] body) throws IOException {
        HandshakeMessageOutput message = new HandshakeMessageOutput(handshakeType, body.length);
        message.write(body);
        message.send(protocol);
    }

    HandshakeMessageOutput(short handshakeType) throws IOException {
        this(handshakeType, 60);
    }

    HandshakeMessageOutput(short handshakeType, int bodyLength) throws IOException {
        super(getLength(bodyLength));
        TlsUtils.checkUint8(handshakeType);
        TlsUtils.writeUint8(handshakeType, (OutputStream) this);
        this.count += 3;
    }

    /* access modifiers changed from: package-private */
    public void send(TlsProtocol protocol) throws IOException {
        int bodyLength = this.count - 4;
        TlsUtils.checkUint24(bodyLength);
        TlsUtils.writeUint24(bodyLength, this.buf, 1);
        protocol.writeHandshakeMessage(this.buf, 0, this.count);
        this.buf = null;
    }

    /* access modifiers changed from: package-private */
    public void prepareClientHello(TlsHandshakeHash handshakeHash, int bindersSize) throws IOException {
        int bodyLength = (this.count - 4) + bindersSize;
        TlsUtils.checkUint24(bodyLength);
        TlsUtils.writeUint24(bodyLength, this.buf, 1);
        handshakeHash.update(this.buf, 0, this.count);
    }

    /* access modifiers changed from: package-private */
    public void sendClientHello(TlsClientProtocol clientProtocol, TlsHandshakeHash handshakeHash, int bindersSize) throws IOException {
        if (bindersSize > 0) {
            handshakeHash.update(this.buf, this.count - bindersSize, bindersSize);
        }
        clientProtocol.writeHandshakeMessage(this.buf, 0, this.count);
        this.buf = null;
    }
}
