package com.mi.car.jsse.easysec.tls;

import java.io.IOException;

public interface TlsAuthentication {
    TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException;

    void notifyServerCertificate(TlsServerCertificate tlsServerCertificate) throws IOException;
}
