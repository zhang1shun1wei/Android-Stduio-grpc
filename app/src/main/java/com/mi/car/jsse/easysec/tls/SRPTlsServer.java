package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import java.io.IOException;
import java.util.Hashtable;

public class SRPTlsServer extends AbstractTlsServer {
    private static final int[] DEFAULT_CIPHER_SUITES = {CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA, CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA, CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA};
    protected byte[] srpIdentity = null;
    protected TlsSRPIdentityManager srpIdentityManager;
    protected TlsSRPLoginParameters srpLoginParameters = null;

    public SRPTlsServer(TlsCrypto crypto, TlsSRPIdentityManager srpIdentityManager2) {
        super(crypto);
        this.srpIdentityManager = srpIdentityManager2;
    }

    /* access modifiers changed from: protected */
    public TlsCredentialedSigner getDSASignerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    /* access modifiers changed from: protected */
    public TlsCredentialedSigner getRSASignerCredentials() throws IOException {
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

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public void processClientExtensions(Hashtable clientExtensions) throws IOException {
        super.processClientExtensions(clientExtensions);
        this.srpIdentity = TlsSRPUtils.getSRPExtension(clientExtensions);
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public int getSelectedCipherSuite() throws IOException {
        int cipherSuite = super.getSelectedCipherSuite();
        if (TlsSRPUtils.isSRPCipherSuite(cipherSuite)) {
            if (this.srpIdentity != null) {
                this.srpLoginParameters = this.srpIdentityManager.getLoginParameters(this.srpIdentity);
            }
            if (this.srpLoginParameters == null) {
                throw new TlsFatalAlert(AlertDescription.unknown_psk_identity);
            }
        }
        return cipherSuite;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public TlsCredentials getCredentials() throws IOException {
        switch (this.context.getSecurityParametersHandshake().getKeyExchangeAlgorithm()) {
            case 21:
                return null;
            case 22:
                return getDSASignerCredentials();
            case 23:
                return getRSASignerCredentials();
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public TlsSRPLoginParameters getSRPLoginParameters() throws IOException {
        return this.srpLoginParameters;
    }
}
