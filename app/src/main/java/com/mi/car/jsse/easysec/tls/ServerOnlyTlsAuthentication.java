package com.mi.car.jsse.easysec.tls;

public abstract class ServerOnlyTlsAuthentication implements TlsAuthentication {
    @Override // com.mi.car.jsse.easysec.tls.TlsAuthentication
    public final TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
        return null;
    }
}
