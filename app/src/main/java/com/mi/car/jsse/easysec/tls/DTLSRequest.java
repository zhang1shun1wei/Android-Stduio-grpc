package com.mi.car.jsse.easysec.tls;

public class DTLSRequest {
    private final ClientHello clientHello;
    private final byte[] message;
    private final long recordSeq;

    DTLSRequest(long recordSeq2, byte[] message2, ClientHello clientHello2) {
        this.recordSeq = recordSeq2;
        this.message = message2;
        this.clientHello = clientHello2;
    }

    /* access modifiers changed from: package-private */
    public ClientHello getClientHello() {
        return this.clientHello;
    }

    /* access modifiers changed from: package-private */
    public byte[] getMessage() {
        return this.message;
    }

    /* access modifiers changed from: package-private */
    public int getMessageSeq() {
        return TlsUtils.readUint16(this.message, 4);
    }

    /* access modifiers changed from: package-private */
    public long getRecordSeq() {
        return this.recordSeq;
    }
}
