package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.io.TeeInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TlsDHEKeyExchange extends AbstractTlsKeyExchange {
    protected TlsAgreement agreement;
    protected TlsDHConfig dhConfig;
    protected TlsDHGroupVerifier dhGroupVerifier;
    protected TlsCertificate serverCertificate;
    protected TlsCredentialedSigner serverCredentials;

    private static int checkKeyExchange(int keyExchange) {
        switch (keyExchange) {
            case 3:
            case 5:
                return keyExchange;
            case 4:
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    public TlsDHEKeyExchange(int keyExchange, TlsDHGroupVerifier dhGroupVerifier2) {
        this(keyExchange, dhGroupVerifier2, null);
    }

    public TlsDHEKeyExchange(int keyExchange, TlsDHConfig dhConfig2) {
        this(keyExchange, null, dhConfig2);
    }

    private TlsDHEKeyExchange(int keyExchange, TlsDHGroupVerifier dhGroupVerifier2, TlsDHConfig dhConfig2) {
        super(checkKeyExchange(keyExchange));
        this.serverCredentials = null;
        this.serverCertificate = null;
        this.dhGroupVerifier = dhGroupVerifier2;
        this.dhConfig = dhConfig2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void skipServerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processServerCredentials(TlsCredentials serverCredentials2) throws IOException {
        this.serverCredentials = TlsUtils.requireSignerCredentials(serverCredentials2);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerCertificate(Certificate serverCertificate2) throws IOException {
        this.serverCertificate = serverCertificate2.getCertificateAt(0);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public boolean requiresServerKeyExchange() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public byte[] generateServerKeyExchange() throws IOException {
        DigestInputBuffer digestBuffer = new DigestInputBuffer();
        TlsDHUtils.writeDHConfig(this.dhConfig, digestBuffer);
        this.agreement = this.context.getCrypto().createDHDomain(this.dhConfig).createDH();
        TlsUtils.writeOpaque16(this.agreement.generateEphemeral(), digestBuffer);
        TlsUtils.generateServerKeyExchangeSignature(this.context, this.serverCredentials, null, digestBuffer);
        return digestBuffer.toByteArray();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerKeyExchange(InputStream input) throws IOException {
        DigestInputBuffer digestBuffer = new DigestInputBuffer();
        InputStream teeIn = new TeeInputStream(input, digestBuffer);
        this.dhConfig = TlsDHUtils.receiveDHConfig(this.context, this.dhGroupVerifier, teeIn);
        byte[] y = TlsUtils.readOpaque16(teeIn, 1);
        TlsUtils.verifyServerKeyExchangeSignature(this.context, input, this.serverCertificate, null, digestBuffer);
        this.agreement = this.context.getCrypto().createDHDomain(this.dhConfig).createDH();
        this.agreement.receivePeerValue(y);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public short[] getClientCertificateTypes() {
        return new short[]{2, 64, 1};
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException {
        TlsUtils.requireSignerCredentials(clientCredentials);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void generateClientKeyExchange(OutputStream output) throws IOException {
        TlsUtils.writeOpaque16(this.agreement.generateEphemeral(), output);
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
