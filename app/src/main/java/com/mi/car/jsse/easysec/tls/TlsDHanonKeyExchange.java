package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TlsDHanonKeyExchange extends AbstractTlsKeyExchange {
    protected TlsAgreement agreement;
    protected TlsDHConfig dhConfig;
    protected TlsDHGroupVerifier dhGroupVerifier;

    private static int checkKeyExchange(int keyExchange) {
        switch (keyExchange) {
            case 11:
                return keyExchange;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    public TlsDHanonKeyExchange(int keyExchange, TlsDHGroupVerifier dhGroupVerifier2) {
        this(keyExchange, dhGroupVerifier2, null);
    }

    public TlsDHanonKeyExchange(int keyExchange, TlsDHConfig dhConfig2) {
        this(keyExchange, null, dhConfig2);
    }

    private TlsDHanonKeyExchange(int keyExchange, TlsDHGroupVerifier dhGroupVerifier2, TlsDHConfig dhConfig2) {
        super(checkKeyExchange(keyExchange));
        this.dhGroupVerifier = dhGroupVerifier2;
        this.dhConfig = dhConfig2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void skipServerCredentials() throws IOException {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerCertificate(Certificate serverCertificate) throws IOException {
        throw new TlsFatalAlert((short) 10);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public boolean requiresServerKeyExchange() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public byte[] generateServerKeyExchange() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsDHUtils.writeDHConfig(this.dhConfig, buf);
        this.agreement = this.context.getCrypto().createDHDomain(this.dhConfig).createDH();
        TlsUtils.writeOpaque16(this.agreement.generateEphemeral(), buf);
        return buf.toByteArray();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerKeyExchange(InputStream input) throws IOException {
        this.dhConfig = TlsDHUtils.receiveDHConfig(this.context, this.dhGroupVerifier, input);
        byte[] y = TlsUtils.readOpaque16(input, 1);
        this.agreement = this.context.getCrypto().createDHDomain(this.dhConfig).createDH();
        this.agreement.receivePeerValue(y);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public short[] getClientCertificateTypes() {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void generateClientKeyExchange(OutputStream output) throws IOException {
        TlsUtils.writeOpaque16(this.agreement.generateEphemeral(), output);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processClientCertificate(Certificate clientCertificate) throws IOException {
        throw new TlsFatalAlert((short) 10);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processClientKeyExchange(InputStream input) throws IOException {
        this.agreement.receivePeerValue(TlsUtils.readOpaque16(input, 1));
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public TlsSecret generatePreMasterSecret() throws IOException {
        return this.agreement.calculateSecret();
    }
}
