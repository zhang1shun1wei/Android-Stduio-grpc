package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.SignedData;
import com.mi.car.jsse.easysec.x509.X509StreamParserSpi;
import com.mi.car.jsse.easysec.x509.util.StreamParsingException;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class X509CertParser extends X509StreamParserSpi {
    private static final PEMUtil PEM_PARSER = new PEMUtil("CERTIFICATE");
    private InputStream currentStream = null;
    private ASN1Set sData = null;
    private int sDataObjectCount = 0;

    private Certificate readDERCertificate(InputStream in) throws IOException, CertificateParsingException {
        ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(in).readObject();
        if (seq.size() <= 1 || !(seq.getObjectAt(0) instanceof ASN1ObjectIdentifier) || !seq.getObjectAt(0).equals(PKCSObjectIdentifiers.signedData)) {
            return new X509CertificateObject(com.mi.car.jsse.easysec.asn1.x509.Certificate.getInstance(seq));
        }
        this.sData = new SignedData(ASN1Sequence.getInstance((ASN1TaggedObject) seq.getObjectAt(1), true)).getCertificates();
        return getCertificate();
    }

    private Certificate getCertificate() throws CertificateParsingException {
        if (this.sData != null) {
            while (this.sDataObjectCount < this.sData.size()) {
                ASN1Set aSN1Set = this.sData;
                int i = this.sDataObjectCount;
                this.sDataObjectCount = i + 1;
                ASN1Encodable obj = aSN1Set.getObjectAt(i);
                if (obj instanceof ASN1Sequence) {
                    return new X509CertificateObject(com.mi.car.jsse.easysec.asn1.x509.Certificate.getInstance(obj));
                }
            }
        }
        return null;
    }

    private Certificate readPEMCertificate(InputStream in) throws IOException, CertificateParsingException {
        ASN1Sequence seq = PEM_PARSER.readPEMObject(in);
        if (seq != null) {
            return new X509CertificateObject(com.mi.car.jsse.easysec.asn1.x509.Certificate.getInstance(seq));
        }
        return null;
    }

    @Override // com.mi.car.jsse.easysec.x509.X509StreamParserSpi
    public void engineInit(InputStream in) {
        this.currentStream = in;
        this.sData = null;
        this.sDataObjectCount = 0;
        if (!this.currentStream.markSupported()) {
            this.currentStream = new BufferedInputStream(this.currentStream);
        }
    }

    @Override // com.mi.car.jsse.easysec.x509.X509StreamParserSpi
    public Object engineRead() throws StreamParsingException {
        try {
            if (this.sData == null) {
                this.currentStream.mark(10);
                int tag = this.currentStream.read();
                if (tag == -1) {
                    return null;
                }
                if (tag != 48) {
                    this.currentStream.reset();
                    return readPEMCertificate(this.currentStream);
                }
                this.currentStream.reset();
                return readDERCertificate(this.currentStream);
            } else if (this.sDataObjectCount != this.sData.size()) {
                return getCertificate();
            } else {
                this.sData = null;
                this.sDataObjectCount = 0;
                return null;
            }
        } catch (Exception e) {
            throw new StreamParsingException(e.toString(), e);
        }
    }

    @Override // com.mi.car.jsse.easysec.x509.X509StreamParserSpi
    public Collection engineReadAll() throws StreamParsingException {
        List certs = new ArrayList();
        while (true) {
            Certificate cert = (Certificate) engineRead();
            if (cert == null) {
                return certs;
            }
            certs.add(cert);
        }
    }
}
