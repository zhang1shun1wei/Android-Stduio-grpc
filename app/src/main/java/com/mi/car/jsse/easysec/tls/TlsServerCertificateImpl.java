package com.mi.car.jsse.easysec.tls;

/* access modifiers changed from: package-private */
public class TlsServerCertificateImpl implements TlsServerCertificate {
    protected Certificate certificate;
    protected CertificateStatus certificateStatus;

    TlsServerCertificateImpl(Certificate certificate2, CertificateStatus certificateStatus2) {
        this.certificate = certificate2;
        this.certificateStatus = certificateStatus2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServerCertificate
    public Certificate getCertificate() {
        return this.certificate;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServerCertificate
    public CertificateStatus getCertificateStatus() {
        return this.certificateStatus;
    }
}
