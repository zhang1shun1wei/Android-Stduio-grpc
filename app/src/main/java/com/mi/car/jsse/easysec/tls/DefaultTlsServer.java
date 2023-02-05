package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import java.io.IOException;

public abstract class DefaultTlsServer extends AbstractTlsServer {
    private static final int[] DEFAULT_CIPHER_SUITES = {CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, 57, 51, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, 61, 60, 53, 47};

    public DefaultTlsServer(TlsCrypto crypto) {
        super(crypto);
    }

    /* access modifiers changed from: protected */
    public TlsCredentialedSigner getDSASignerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    /* access modifiers changed from: protected */
    public TlsCredentialedSigner getECDSASignerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    /* access modifiers changed from: protected */
    public TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    /* access modifiers changed from: protected */
    public TlsCredentialedSigner getRSASignerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public int[] getSupportedCipherSuites() {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public TlsCredentials getCredentials() throws IOException {
        switch (this.context.getSecurityParametersHandshake().getKeyExchangeAlgorithm()) {
            case 1:
                return getRSAEncryptionCredentials();
            case 3:
                return getDSASignerCredentials();
            case 5:
            case 19:
                return getRSASignerCredentials();
            case 11:
            case 20:
                return null;
            case 17:
                return getECDSASignerCredentials();
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }
}
