package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.io.TeeInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TlsECDHEKeyExchange extends AbstractTlsKeyExchange {
    protected TlsAgreement agreement;
    protected TlsECConfig ecConfig;
    protected TlsCertificate serverCertificate;
    protected TlsCredentialedSigner serverCredentials;

    private static int checkKeyExchange(int keyExchange) {
        switch (keyExchange) {
            case 17:
            case 19:
                return keyExchange;
            case 18:
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    public TlsECDHEKeyExchange(int keyExchange) {
        this(keyExchange, null);
    }

    public TlsECDHEKeyExchange(int keyExchange, TlsECConfig ecConfig2) {
        super(checkKeyExchange(keyExchange));
        this.serverCredentials = null;
        this.serverCertificate = null;
        this.ecConfig = ecConfig2;
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
        TlsECCUtils.writeECConfig(this.ecConfig, digestBuffer);
        this.agreement = this.context.getCrypto().createECDomain(this.ecConfig).createECDH();
        generateEphemeral(digestBuffer);
        TlsUtils.generateServerKeyExchangeSignature(this.context, this.serverCredentials, null, digestBuffer);
        return digestBuffer.toByteArray();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerKeyExchange(InputStream input) throws IOException {
        DigestInputBuffer digestBuffer = new DigestInputBuffer();
        InputStream teeIn = new TeeInputStream(input, digestBuffer);
        this.ecConfig = TlsECCUtils.receiveECDHConfig(this.context, teeIn);
        byte[] point = TlsUtils.readOpaque8(teeIn, 1);
        TlsUtils.verifyServerKeyExchangeSignature(this.context, input, this.serverCertificate, null, digestBuffer);
        this.agreement = this.context.getCrypto().createECDomain(this.ecConfig).createECDH();
        processEphemeral(point);
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
        generateEphemeral(output);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processClientKeyExchange(InputStream input) throws IOException {
        processEphemeral(TlsUtils.readOpaque8(input, 1));
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public TlsSecret generatePreMasterSecret() throws IOException {
        return this.agreement.calculateSecret();
    }

    /* access modifiers changed from: protected */
    public void generateEphemeral(OutputStream output) throws IOException {
        TlsUtils.writeOpaque8(this.agreement.generateEphemeral(), output);
    }

    /* access modifiers changed from: protected */
    public void processEphemeral(byte[] point) throws IOException {
        TlsECCUtils.checkPointEncoding(this.ecConfig.getNamedGroup(), point);
        this.agreement.receivePeerValue(point);
    }
}
