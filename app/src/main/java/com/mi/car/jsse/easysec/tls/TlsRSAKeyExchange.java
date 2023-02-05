package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncryptor;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TlsRSAKeyExchange extends AbstractTlsKeyExchange {
    protected TlsSecret preMasterSecret;
    protected TlsCredentialedDecryptor serverCredentials = null;
    protected TlsEncryptor serverEncryptor;

    private static int checkKeyExchange(int keyExchange) {
        switch (keyExchange) {
            case 1:
                return keyExchange;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    public TlsRSAKeyExchange(int keyExchange) {
        super(checkKeyExchange(keyExchange));
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void skipServerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processServerCredentials(TlsCredentials serverCredentials2) throws IOException {
        this.serverCredentials = TlsUtils.requireDecryptorCredentials(serverCredentials2);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerCertificate(Certificate serverCertificate) throws IOException {
        this.serverEncryptor = serverCertificate.getCertificateAt(0).createEncryptor(3);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public short[] getClientCertificateTypes() {
        return new short[]{1, 2, 64};
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException {
        TlsUtils.requireSignerCredentials(clientCredentials);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void generateClientKeyExchange(OutputStream output) throws IOException {
        this.preMasterSecret = TlsUtils.generateEncryptedPreMasterSecret(this.context, this.serverEncryptor, output);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processClientKeyExchange(InputStream input) throws IOException {
        this.preMasterSecret = this.serverCredentials.decrypt(new TlsCryptoParameters(this.context), TlsUtils.readEncryptedPMS(this.context, input));
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public TlsSecret generatePreMasterSecret() throws IOException {
        TlsSecret tmp = this.preMasterSecret;
        this.preMasterSecret = null;
        return tmp;
    }
}
