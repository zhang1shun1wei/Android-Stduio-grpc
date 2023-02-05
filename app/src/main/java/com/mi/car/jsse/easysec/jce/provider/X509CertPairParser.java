package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.x509.CertificatePair;
import com.mi.car.jsse.easysec.x509.X509CertificatePair;
import com.mi.car.jsse.easysec.x509.X509StreamParserSpi;
import com.mi.car.jsse.easysec.x509.util.StreamParsingException;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class X509CertPairParser extends X509StreamParserSpi {
    private InputStream currentStream = null;

    private X509CertificatePair readDERCrossCertificatePair(InputStream in) throws IOException, CertificateParsingException {
        return new X509CertificatePair(CertificatePair.getInstance((ASN1Sequence) new ASN1InputStream(in).readObject()));
    }

    @Override // com.mi.car.jsse.easysec.x509.X509StreamParserSpi
    public void engineInit(InputStream in) {
        this.currentStream = in;
        if (!this.currentStream.markSupported()) {
            this.currentStream = new BufferedInputStream(this.currentStream);
        }
    }

    @Override // com.mi.car.jsse.easysec.x509.X509StreamParserSpi
    public Object engineRead() throws StreamParsingException {
        try {
            this.currentStream.mark(10);
            if (this.currentStream.read() == -1) {
                return null;
            }
            this.currentStream.reset();
            return readDERCrossCertificatePair(this.currentStream);
        } catch (Exception e) {
            throw new StreamParsingException(e.toString(), e);
        }
    }

    @Override // com.mi.car.jsse.easysec.x509.X509StreamParserSpi
    public Collection engineReadAll() throws StreamParsingException {
        List certs = new ArrayList();
        while (true) {
            X509CertificatePair pair = (X509CertificatePair) engineRead();
            if (pair == null) {
                return certs;
            }
            certs.add(pair);
        }
    }
}
