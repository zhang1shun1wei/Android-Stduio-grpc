package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TlsECDHKeyExchange extends AbstractTlsKeyExchange {
    protected TlsCredentialedAgreement agreementCredentials;
    protected TlsCertificate ecdhPeerCertificate;

    private static int checkKeyExchange(int keyExchange) {
        switch (keyExchange) {
            case 16:
            case 18:
                return keyExchange;
            case 17:
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    public TlsECDHKeyExchange(int keyExchange) {
        super(checkKeyExchange(keyExchange));
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void skipServerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException {
        this.agreementCredentials = TlsUtils.requireAgreementCredentials(serverCredentials);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerCertificate(Certificate serverCertificate) throws IOException {
        this.ecdhPeerCertificate = serverCertificate.getCertificateAt(0).checkUsageInRole(2);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public short[] getClientCertificateTypes() {
        return new short[]{66, 65};
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void skipClientCredentials() throws IOException {
        throw new TlsFatalAlert((short) 10);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException {
        this.agreementCredentials = TlsUtils.requireAgreementCredentials(clientCredentials);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void generateClientKeyExchange(OutputStream output) throws IOException {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processClientCertificate(Certificate clientCertificate) throws IOException {
        this.ecdhPeerCertificate = clientCertificate.getCertificateAt(0).checkUsageInRole(2);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processClientKeyExchange(InputStream input) throws IOException {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public boolean requiresCertificateVerify() {
        return false;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public TlsSecret generatePreMasterSecret() throws IOException {
        return this.agreementCredentials.generateAgreement(this.ecdhPeerCertificate);
    }
}
