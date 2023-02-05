package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.InputStream;

public abstract class AbstractTlsKeyExchange implements TlsKeyExchange {
    protected TlsContext context;
    protected int keyExchange;

    protected AbstractTlsKeyExchange(int keyExchange2) {
        this.keyExchange = keyExchange2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void init(TlsContext context2) {
        this.context = context2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processServerCertificate(Certificate serverCertificate) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public boolean requiresServerKeyExchange() {
        return false;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public byte[] generateServerKeyExchange() throws IOException {
        if (!requiresServerKeyExchange()) {
            return null;
        }
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void skipServerKeyExchange() throws IOException {
        if (requiresServerKeyExchange()) {
            throw new TlsFatalAlert((short) 10);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processServerKeyExchange(InputStream input) throws IOException {
        if (!requiresServerKeyExchange()) {
            throw new TlsFatalAlert((short) 10);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public short[] getClientCertificateTypes() {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void skipClientCredentials() throws IOException {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processClientCertificate(Certificate clientCertificate) throws IOException {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processClientKeyExchange(InputStream input) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public boolean requiresCertificateVerify() {
        return true;
    }
}
