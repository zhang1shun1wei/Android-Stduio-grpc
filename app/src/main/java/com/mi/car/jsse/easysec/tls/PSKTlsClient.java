package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import java.io.IOException;

public class PSKTlsClient extends AbstractTlsClient {
    private static final int[] DEFAULT_CIPHER_SUITES = {CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA};
    protected TlsPSKIdentity pskIdentity;

    public PSKTlsClient(TlsCrypto crypto, byte[] identity, byte[] psk) {
        this(crypto, new BasicTlsPSKIdentity(identity, psk));
    }

    public PSKTlsClient(TlsCrypto crypto, TlsPSKIdentity pskIdentity2) {
        super(crypto);
        this.pskIdentity = pskIdentity2;
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

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsClient, com.mi.car.jsse.easysec.tls.TlsClient
    public TlsPSKIdentity getPSKIdentity() {
        return this.pskIdentity;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsClient
    public TlsAuthentication getAuthentication() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }
}
