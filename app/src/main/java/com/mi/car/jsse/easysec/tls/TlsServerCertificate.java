package com.mi.car.jsse.easysec.tls;

public interface TlsServerCertificate {
    Certificate getCertificate();

    CertificateStatus getCertificateStatus();
}
