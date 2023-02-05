package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TlsECDHanonKeyExchange extends AbstractTlsKeyExchange {
    protected TlsAgreement agreement;
    protected TlsECConfig ecConfig;

    private static int checkKeyExchange(int keyExchange) {
        switch (keyExchange) {
            case 20:
                return keyExchange;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    public TlsECDHanonKeyExchange(int keyExchange) {
        this(keyExchange, null);
    }

    public TlsECDHanonKeyExchange(int keyExchange, TlsECConfig ecConfig2) {
        super(checkKeyExchange(keyExchange));
        this.ecConfig = ecConfig2;
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
        TlsECCUtils.writeECConfig(this.ecConfig, buf);
        this.agreement = this.context.getCrypto().createECDomain(this.ecConfig).createECDH();
        generateEphemeral(buf);
        return buf.toByteArray();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerKeyExchange(InputStream input) throws IOException {
        this.ecConfig = TlsECCUtils.receiveECDHConfig(this.context, input);
        byte[] point = TlsUtils.readOpaque8(input, 1);
        this.agreement = this.context.getCrypto().createECDomain(this.ecConfig).createECDH();
        processEphemeral(point);
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
        generateEphemeral(output);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processClientCertificate(Certificate clientCertificate) throws IOException {
        throw new TlsFatalAlert((short) 10);
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
