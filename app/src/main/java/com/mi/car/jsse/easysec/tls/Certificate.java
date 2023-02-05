package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

public class Certificate {
    private static final TlsCertificate[] EMPTY_CERTS = new TlsCertificate[0];
    private static final CertificateEntry[] EMPTY_CERT_ENTRIES = new CertificateEntry[0];
    public static final Certificate EMPTY_CHAIN = new Certificate(EMPTY_CERTS);
    public static final Certificate EMPTY_CHAIN_TLS13 = new Certificate(TlsUtils.EMPTY_BYTES, EMPTY_CERT_ENTRIES);
    protected final CertificateEntry[] certificateEntryList;
    protected final byte[] certificateRequestContext;

    public static class ParseOptions {
        private int maxChainLength = Integer.MAX_VALUE;

        public int getMaxChainLength() {
            return this.maxChainLength;
        }

        public ParseOptions setMaxChainLength(int maxChainLength2) {
            this.maxChainLength = maxChainLength2;
            return this;
        }
    }

    private static CertificateEntry[] convert(TlsCertificate[] certificateList) {
        if (TlsUtils.isNullOrContainsNull(certificateList)) {
            throw new NullPointerException("'certificateList' cannot be null or contain any nulls");
        }
        int count = certificateList.length;
        CertificateEntry[] result = new CertificateEntry[count];
        for (int i = 0; i < count; i++) {
            result[i] = new CertificateEntry(certificateList[i], null);
        }
        return result;
    }

    public Certificate(TlsCertificate[] certificateList) {
        this(null, convert(certificateList));
    }

    public Certificate(byte[] certificateRequestContext2, CertificateEntry[] certificateEntryList2) {
        if (certificateRequestContext2 != null && !TlsUtils.isValidUint8(certificateRequestContext2.length)) {
            throw new IllegalArgumentException("'certificateRequestContext' cannot be longer than 255");
        } else if (TlsUtils.isNullOrContainsNull(certificateEntryList2)) {
            throw new NullPointerException("'certificateEntryList' cannot be null or contain any nulls");
        } else {
            this.certificateRequestContext = TlsUtils.clone(certificateRequestContext2);
            this.certificateEntryList = certificateEntryList2;
        }
    }

    public byte[] getCertificateRequestContext() {
        return TlsUtils.clone(this.certificateRequestContext);
    }

    public TlsCertificate[] getCertificateList() {
        return cloneCertificateList();
    }

    public TlsCertificate getCertificateAt(int index) {
        return this.certificateEntryList[index].getCertificate();
    }

    public CertificateEntry getCertificateEntryAt(int index) {
        return this.certificateEntryList[index];
    }

    public CertificateEntry[] getCertificateEntryList() {
        return cloneCertificateEntryList();
    }

    public short getCertificateType() {
        return 0;
    }

    public int getLength() {
        return this.certificateEntryList.length;
    }

    public boolean isEmpty() {
        return this.certificateEntryList.length == 0;
    }

    public void encode(TlsContext context, OutputStream messageOutput, OutputStream endPointHashOutput) throws IOException {
        byte[] extEncoding;
        boolean isTLSv13 = TlsUtils.isTLSv13(context);
        if ((this.certificateRequestContext != null) != isTLSv13) {
            throw new IllegalStateException();
        }
        if (isTLSv13) {
            TlsUtils.writeOpaque8(this.certificateRequestContext, messageOutput);
        }
        int count = this.certificateEntryList.length;
        Vector certEncodings = new Vector(count);
        Vector extEncodings = isTLSv13 ? new Vector(count) : null;
        long totalLength = 0;
        for (int i = 0; i < count; i++) {
            CertificateEntry entry = this.certificateEntryList[i];
            TlsCertificate cert = entry.getCertificate();
            byte[] derEncoding = cert.getEncoded();
            if (i == 0 && endPointHashOutput != null) {
                calculateEndPointHash(context, cert, derEncoding, endPointHashOutput);
            }
            certEncodings.addElement(derEncoding);
            totalLength = totalLength + ((long) derEncoding.length) + 3;
            if (isTLSv13) {
                Hashtable extensions = entry.getExtensions();
                if (extensions == null) {
                    extEncoding = TlsUtils.EMPTY_BYTES;
                } else {
                    extEncoding = TlsProtocol.writeExtensionsData(extensions);
                }
                extEncodings.addElement(extEncoding);
                totalLength = totalLength + ((long) extEncoding.length) + 2;
            }
        }
        TlsUtils.checkUint24(totalLength);
        TlsUtils.writeUint24((int) totalLength, messageOutput);
        for (int i2 = 0; i2 < count; i2++) {
            TlsUtils.writeOpaque24((byte[]) certEncodings.elementAt(i2), messageOutput);
            if (isTLSv13) {
                TlsUtils.writeOpaque16((byte[]) extEncodings.elementAt(i2), messageOutput);
            }
        }
    }

    public static Certificate parse(TlsContext context, InputStream messageInput, OutputStream endPointHashOutput) throws IOException {
        return parse(new ParseOptions(), context, messageInput, endPointHashOutput);
    }

    public static Certificate parse(ParseOptions options, TlsContext context, InputStream messageInput, OutputStream endPointHashOutput) throws IOException {
        boolean isTLSv13 = TlsUtils.isTLSv13(context.getSecurityParameters().getNegotiatedVersion());
        byte[] certificateRequestContext2 = null;
        if (isTLSv13) {
            certificateRequestContext2 = TlsUtils.readOpaque8(messageInput);
        }
        int totalLength = TlsUtils.readUint24(messageInput);
        if (totalLength != 0) {
            ByteArrayInputStream buf = new ByteArrayInputStream(TlsUtils.readFully(totalLength, messageInput));
            TlsCrypto crypto = context.getCrypto();
            int maxChainLength = Math.max(1, options.getMaxChainLength());
            Vector certificate_list = new Vector();
            while (buf.available() > 0) {
                if (certificate_list.size() >= maxChainLength) {
                    throw new TlsFatalAlert((short) 80, "Certificate chain longer than maximum (" + maxChainLength + ")");
                }
                byte[] derEncoding = TlsUtils.readOpaque24(buf, 1);
                TlsCertificate cert = crypto.createCertificate(derEncoding);
                if (certificate_list.isEmpty() && endPointHashOutput != null) {
                    calculateEndPointHash(context, cert, derEncoding, endPointHashOutput);
                }
                Hashtable extensions = null;
                if (isTLSv13) {
                    extensions = TlsProtocol.readExtensionsData13(11, TlsUtils.readOpaque16(buf));
                }
                certificate_list.addElement(new CertificateEntry(cert, extensions));
            }
            CertificateEntry[] certificateList = new CertificateEntry[certificate_list.size()];
            for (int i = 0; i < certificate_list.size(); i++) {
                certificateList[i] = (CertificateEntry) certificate_list.elementAt(i);
            }
            return new Certificate(certificateRequestContext2, certificateList);
        } else if (!isTLSv13) {
            return EMPTY_CHAIN;
        } else {
            return certificateRequestContext2.length < 1 ? EMPTY_CHAIN_TLS13 : new Certificate(certificateRequestContext2, EMPTY_CERT_ENTRIES);
        }
    }

    protected static void calculateEndPointHash(TlsContext context, TlsCertificate cert, byte[] encoding, OutputStream output) throws IOException {
        byte[] endPointHash = TlsUtils.calculateEndPointHash(context, cert, encoding);
        if (endPointHash != null && endPointHash.length > 0) {
            output.write(endPointHash);
        }
    }

    /* access modifiers changed from: protected */
    public TlsCertificate[] cloneCertificateList() {
        int count = this.certificateEntryList.length;
        if (count == 0) {
            return EMPTY_CERTS;
        }
        TlsCertificate[] result = new TlsCertificate[count];
        for (int i = 0; i < count; i++) {
            result[i] = this.certificateEntryList[i].getCertificate();
        }
        return result;
    }

    /* access modifiers changed from: protected */
    public CertificateEntry[] cloneCertificateEntryList() {
        int count = this.certificateEntryList.length;
        if (count == 0) {
            return EMPTY_CERT_ENTRIES;
        }
        CertificateEntry[] result = new CertificateEntry[count];
        System.arraycopy(this.certificateEntryList, 0, result, 0, count);
        return result;
    }
}
