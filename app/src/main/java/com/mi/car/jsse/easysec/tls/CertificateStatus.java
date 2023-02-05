package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ocsp.OCSPResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

public class CertificateStatus {
    protected short statusType;
    protected Object response;

    public CertificateStatus(short statusType, Object response) {
        if (!isCorrectType(statusType, response)) {
            throw new IllegalArgumentException("'response' is not an instance of the correct type");
        } else {
            this.statusType = statusType;
            this.response = response;
        }
    }

    public short getStatusType() {
        return this.statusType;
    }

    public Object getResponse() {
        return this.response;
    }

    public OCSPResponse getOCSPResponse() {
        if (!isCorrectType((short)1, this.response)) {
            throw new IllegalStateException("'response' is not an OCSPResponse");
        } else {
            return (OCSPResponse)this.response;
        }
    }

    public Vector getOCSPResponseList() {
        if (!isCorrectType((short)2, this.response)) {
            throw new IllegalStateException("'response' is not an OCSPResponseList");
        } else {
            return (Vector)this.response;
        }
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeUint8(this.statusType, output);
        switch(this.statusType) {
            case 1:
                OCSPResponse ocspResponse = (OCSPResponse)this.response;
                byte[] derEncoding = ocspResponse.getEncoded("DER");
                TlsUtils.writeOpaque24(derEncoding, output);
                return;
            case 2:
                Vector ocspResponseList = (Vector)this.response;
                int count = ocspResponseList.size();
                Vector derEncodings = new Vector(count);
                long totalLength = 0L;

                int i;
                for(i = 0; i < count; ++i) {
                    OCSPResponse ocspResponse1 = (OCSPResponse)ocspResponseList.elementAt(i);
                    if (ocspResponse1 == null) {
                        derEncodings.addElement(TlsUtils.EMPTY_BYTES);
                    } else {
                        byte[] derEncoding1 = ocspResponse1.getEncoded("DER");
                        derEncodings.addElement(derEncoding1);
                        totalLength += (long)derEncoding1.length;
                    }

                    totalLength += 3L;
                }

                TlsUtils.checkUint24(totalLength);
                TlsUtils.writeUint24((int)totalLength, output);

                for(i = 0; i < count; ++i) {
                    byte[] derEncoding1 = (byte[])((byte[])derEncodings.elementAt(i));
                    TlsUtils.writeOpaque24(derEncoding1, output);
                }

                return;
            default:
                throw new TlsFatalAlert((short)80);
        }
    }

    public static CertificateStatus parse(TlsContext context, InputStream input) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        Certificate peerCertificate = securityParameters.getPeerCertificate();
        if (null != peerCertificate && !peerCertificate.isEmpty() && 0 == peerCertificate.getCertificateType()) {
            int certificateCount = peerCertificate.getLength();
            int statusRequestVersion = securityParameters.getStatusRequestVersion();
            short status_type = TlsUtils.readUint8(input);
            Object response;
            byte[] ocsp_response_list;
            switch(status_type) {
                case 1:
                    requireStatusRequestVersion(1, statusRequestVersion);
                    ocsp_response_list = TlsUtils.readOpaque24(input, 1);
                    response = parseOCSPResponse(ocsp_response_list);
                    break;
                case 2:
                    requireStatusRequestVersion(2, statusRequestVersion);
                    ocsp_response_list = TlsUtils.readOpaque24(input, 1);
                    ByteArrayInputStream buf = new ByteArrayInputStream(ocsp_response_list);
                    Vector ocspResponseList = new Vector();

                    while(buf.available() > 0) {
                        if (ocspResponseList.size() >= certificateCount) {
                            throw new TlsFatalAlert((short)47);
                        }

                        int length = TlsUtils.readUint24(buf);
                        if (length < 1) {
                            ocspResponseList.addElement((Object)null);
                        } else {
                            byte[] derEncoding = TlsUtils.readFully(length, buf);
                            ocspResponseList.addElement(parseOCSPResponse(derEncoding));
                        }
                    }

                    ocspResponseList.trimToSize();
                    response = ocspResponseList;
                    break;
                default:
                    throw new TlsFatalAlert((short)50);
            }

            return new CertificateStatus(status_type, response);
        } else {
            throw new TlsFatalAlert((short)80);
        }
    }

    protected static boolean isCorrectType(short statusType, Object response) {
        switch(statusType) {
            case 1:
                return response instanceof OCSPResponse;
            case 2:
                return isOCSPResponseList(response);
            default:
                throw new IllegalArgumentException("'statusType' is an unsupported CertificateStatusType");
        }
    }

    protected static boolean isOCSPResponseList(Object response) {
        if (!(response instanceof Vector)) {
            return false;
        } else {
            Vector v = (Vector)response;
            int count = v.size();
            if (count < 1) {
                return false;
            } else {
                for(int i = 0; i < count; ++i) {
                    Object e = v.elementAt(i);
                    if (null != e && !(e instanceof OCSPResponse)) {
                        return false;
                    }
                }

                return true;
            }
        }
    }

    protected static OCSPResponse parseOCSPResponse(byte[] derEncoding) throws IOException {
        ASN1Primitive asn1 = TlsUtils.readASN1Object(derEncoding);
        OCSPResponse ocspResponse = OCSPResponse.getInstance(asn1);
        TlsUtils.requireDEREncoding(ocspResponse, derEncoding);
        return ocspResponse;
    }

    protected static void requireStatusRequestVersion(int minVersion, int statusRequestVersion) throws IOException {
        if (statusRequestVersion < minVersion) {
            throw new TlsFatalAlert((short)50);
        }
    }
}