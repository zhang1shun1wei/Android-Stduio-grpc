package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

public class CertificateRequest {
    protected final Vector certificateAuthorities;
    protected final byte[] certificateRequestContext;
    protected final short[] certificateTypes;
    protected final Vector supportedSignatureAlgorithms;
    protected final Vector supportedSignatureAlgorithmsCert;

    private static Vector checkSupportedSignatureAlgorithms(Vector supportedSignatureAlgorithms2, short alertDescription) throws IOException {
        if (supportedSignatureAlgorithms2 != null) {
            return supportedSignatureAlgorithms2;
        }
        throw new TlsFatalAlert(alertDescription, "'signature_algorithms' is required");
    }

    public CertificateRequest(short[] certificateTypes2, Vector supportedSignatureAlgorithms2, Vector certificateAuthorities2) {
        this(null, certificateTypes2, supportedSignatureAlgorithms2, null, certificateAuthorities2);
    }

    public CertificateRequest(byte[] certificateRequestContext2, Vector supportedSignatureAlgorithms2, Vector supportedSignatureAlgorithmsCert2, Vector certificateAuthorities2) throws IOException {
        this(certificateRequestContext2, null, checkSupportedSignatureAlgorithms(supportedSignatureAlgorithms2, (short) 80), supportedSignatureAlgorithmsCert2, certificateAuthorities2);
    }

    private CertificateRequest(byte[] certificateRequestContext2, short[] certificateTypes2, Vector supportedSignatureAlgorithms2, Vector supportedSignatureAlgorithmsCert2, Vector certificateAuthorities2) {
        if (certificateRequestContext2 != null && !TlsUtils.isValidUint8(certificateRequestContext2.length)) {
            throw new IllegalArgumentException("'certificateRequestContext' cannot be longer than 255");
        } else if (certificateTypes2 == null || (certificateTypes2.length >= 1 && TlsUtils.isValidUint8(certificateTypes2.length))) {
            this.certificateRequestContext = TlsUtils.clone(certificateRequestContext2);
            this.certificateTypes = certificateTypes2;
            this.supportedSignatureAlgorithms = supportedSignatureAlgorithms2;
            this.supportedSignatureAlgorithmsCert = supportedSignatureAlgorithmsCert2;
            this.certificateAuthorities = certificateAuthorities2;
        } else {
            throw new IllegalArgumentException("'certificateTypes' should have length from 1 to 255");
        }
    }

    public byte[] getCertificateRequestContext() {
        return TlsUtils.clone(this.certificateRequestContext);
    }

    public short[] getCertificateTypes() {
        return this.certificateTypes;
    }

    public Vector getSupportedSignatureAlgorithms() {
        return this.supportedSignatureAlgorithms;
    }

    public Vector getSupportedSignatureAlgorithmsCert() {
        return this.supportedSignatureAlgorithmsCert;
    }

    public Vector getCertificateAuthorities() {
        return this.certificateAuthorities;
    }

    public boolean hasCertificateRequestContext(byte[] certificateRequestContext2) {
        return Arrays.areEqual(this.certificateRequestContext, certificateRequestContext2);
    }

    public void encode(TlsContext context, OutputStream output) throws IOException {
        boolean z = true;
        ProtocolVersion negotiatedVersion = context.getServerVersion();
        boolean isTLSv12 = TlsUtils.isTLSv12(negotiatedVersion);
        boolean isTLSv13 = TlsUtils.isTLSv13(negotiatedVersion);
        if (isTLSv13 == (this.certificateRequestContext != null)) {
            if (isTLSv13 == (this.certificateTypes == null)) {
                if (this.supportedSignatureAlgorithms == null) {
                    z = false;
                }
                if (isTLSv12 == z && (isTLSv13 || this.supportedSignatureAlgorithmsCert == null)) {
                    if (isTLSv13) {
                        TlsUtils.writeOpaque8(this.certificateRequestContext, output);
                        Hashtable extensions = new Hashtable();
                        TlsExtensionsUtils.addSignatureAlgorithmsExtension(extensions, this.supportedSignatureAlgorithms);
                        if (this.supportedSignatureAlgorithmsCert != null) {
                            TlsExtensionsUtils.addSignatureAlgorithmsCertExtension(extensions, this.supportedSignatureAlgorithmsCert);
                        }
                        if (this.certificateAuthorities != null) {
                            TlsExtensionsUtils.addCertificateAuthoritiesExtension(extensions, this.certificateAuthorities);
                        }
                        TlsUtils.writeOpaque16(TlsProtocol.writeExtensionsData(extensions), output);
                        return;
                    }
                    TlsUtils.writeUint8ArrayWithUint8Length(this.certificateTypes, output);
                    if (isTLSv12) {
                        TlsUtils.encodeSupportedSignatureAlgorithms(this.supportedSignatureAlgorithms, output);
                    }
                    if (this.certificateAuthorities == null || this.certificateAuthorities.isEmpty()) {
                        TlsUtils.writeUint16(0, output);
                        return;
                    }
                    Vector derEncodings = new Vector(this.certificateAuthorities.size());
                    int totalLength = 0;
                    for (int i = 0; i < this.certificateAuthorities.size(); i++) {
                        byte[] derEncoding = ((X500Name) this.certificateAuthorities.elementAt(i)).getEncoded("DER");
                        derEncodings.addElement(derEncoding);
                        totalLength += derEncoding.length + 2;
                    }
                    TlsUtils.checkUint16(totalLength);
                    TlsUtils.writeUint16(totalLength, output);
                    for (int i2 = 0; i2 < derEncodings.size(); i2++) {
                        TlsUtils.writeOpaque16((byte[]) derEncodings.elementAt(i2), output);
                    }
                    return;
                }
            }
        }
        throw new IllegalStateException();
    }

    public static CertificateRequest parse(TlsContext context, InputStream input) throws IOException {
        ProtocolVersion negotiatedVersion = context.getServerVersion();
        if (TlsUtils.isTLSv13(negotiatedVersion)) {
            byte[] certificateRequestContext2 = TlsUtils.readOpaque8(input);
            Hashtable extensions = TlsProtocol.readExtensionsData13(13, TlsUtils.readOpaque16(input));
            return new CertificateRequest(certificateRequestContext2, checkSupportedSignatureAlgorithms(TlsExtensionsUtils.getSignatureAlgorithmsExtension(extensions), AlertDescription.missing_extension), TlsExtensionsUtils.getSignatureAlgorithmsCertExtension(extensions), TlsExtensionsUtils.getCertificateAuthoritiesExtension(extensions));
        }
        boolean isTLSv12 = TlsUtils.isTLSv12(negotiatedVersion);
        short[] certificateTypes2 = TlsUtils.readUint8ArrayWithUint8Length(input, 1);
        Vector supportedSignatureAlgorithms2 = null;
        if (isTLSv12) {
            supportedSignatureAlgorithms2 = TlsUtils.parseSupportedSignatureAlgorithms(input);
        }
        Vector certificateAuthorities2 = null;
        byte[] certAuthData = TlsUtils.readOpaque16(input);
        if (certAuthData.length > 0) {
            certificateAuthorities2 = new Vector();
            ByteArrayInputStream bis = new ByteArrayInputStream(certAuthData);
            do {
                byte[] derEncoding = TlsUtils.readOpaque16(bis, 1);
                X500Name ca = X500Name.getInstance(TlsUtils.readASN1Object(derEncoding));
                TlsUtils.requireDEREncoding(ca, derEncoding);
                certificateAuthorities2.addElement(ca);
            } while (bis.available() > 0);
        }
        return new CertificateRequest(certificateTypes2, supportedSignatureAlgorithms2, certificateAuthorities2);
    }
}
