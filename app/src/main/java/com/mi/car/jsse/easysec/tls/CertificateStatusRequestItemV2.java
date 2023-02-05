package com.mi.car.jsse.easysec.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class CertificateStatusRequestItemV2 {
    protected Object request;
    protected short statusType;

    public CertificateStatusRequestItemV2(short statusType2, Object request2) {
        if (!isCorrectType(statusType2, request2)) {
            throw new IllegalArgumentException("'request' is not an instance of the correct type");
        }
        this.statusType = statusType2;
        this.request = request2;
    }

    public short getStatusType() {
        return this.statusType;
    }

    public Object getRequest() {
        return this.request;
    }

    public OCSPStatusRequest getOCSPStatusRequest() {
        if (this.request instanceof OCSPStatusRequest) {
            return (OCSPStatusRequest) this.request;
        }
        throw new IllegalStateException("'request' is not an OCSPStatusRequest");
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeUint8(this.statusType, output);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        switch (this.statusType) {
            case 1:
            case 2:
                ((OCSPStatusRequest) this.request).encode(buf);
                TlsUtils.writeOpaque16(buf.toByteArray(), output);
                return;
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    public static CertificateStatusRequestItemV2 parse(InputStream input) throws IOException {
        short status_type = TlsUtils.readUint8(input);
        ByteArrayInputStream buf = new ByteArrayInputStream(TlsUtils.readOpaque16(input));
        switch (status_type) {
            case 1:
            case 2:
                OCSPStatusRequest request2 = OCSPStatusRequest.parse(buf);
                TlsProtocol.assertEmpty(buf);
                return new CertificateStatusRequestItemV2(status_type, request2);
            default:
                throw new TlsFatalAlert((short) 50);
        }
    }

    protected static boolean isCorrectType(short statusType2, Object request2) {
        switch (statusType2) {
            case 1:
            case 2:
                return request2 instanceof OCSPStatusRequest;
            default:
                throw new IllegalArgumentException("'statusType' is an unsupported CertificateStatusType");
        }
    }
}
