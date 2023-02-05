package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import java.io.IOException;

public class PSKTlsServer extends AbstractTlsServer {
    private static final int[] DEFAULT_CIPHER_SUITES = {CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA};
    protected TlsPSKIdentityManager pskIdentityManager;

    public PSKTlsServer(TlsCrypto crypto, TlsPSKIdentityManager pskIdentityManager2) {
        super(crypto);
        this.pskIdentityManager = pskIdentityManager2;
    }

    /* access modifiers changed from: protected */
    public TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public ProtocolVersion[] getSupportedVersions() {
        return ProtocolVersion.TLSv12.downTo(ProtocolVersion.TLSv10);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public int[] getSupportedCipherSuites() {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }

    public ProtocolVersion getMaximumVersion() {
        return ProtocolVersion.TLSv12;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public TlsCredentials getCredentials() throws IOException {
        switch (this.context.getSecurityParametersHandshake().getKeyExchangeAlgorithm()) {
            case 13:
            case 14:
            case 24:
                return null;
            case 15:
                return getRSAEncryptionCredentials();
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public TlsPSKIdentityManager getPSKIdentityManager() {
        return this.pskIdentityManager;
    }
}
