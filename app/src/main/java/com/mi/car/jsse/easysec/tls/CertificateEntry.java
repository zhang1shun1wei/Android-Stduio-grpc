package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import java.util.Hashtable;

public class CertificateEntry {
    protected final TlsCertificate certificate;
    protected final Hashtable extensions;

    public CertificateEntry(TlsCertificate certificate2, Hashtable extensions2) {
        if (certificate2 == null) {
            throw new NullPointerException("'certificate' cannot be null");
        }
        this.certificate = certificate2;
        this.extensions = extensions2;
    }

    public TlsCertificate getCertificate() {
        return this.certificate;
    }

    public Hashtable getExtensions() {
        return this.extensions;
    }
}
