package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import java.io.IOException;
import java.util.Hashtable;

public class SRPTlsClient extends AbstractTlsClient {
    private static final int[] DEFAULT_CIPHER_SUITES = {49182};
    protected TlsSRPIdentity srpIdentity;

    public SRPTlsClient(TlsCrypto crypto, byte[] identity, byte[] password) {
        this(crypto, new BasicTlsSRPIdentity(identity, password));
    }

    public SRPTlsClient(TlsCrypto crypto, TlsSRPIdentity srpIdentity2) {
        super(crypto);
        this.srpIdentity = srpIdentity2;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public int[] getSupportedCipherSuites() {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public ProtocolVersion[] getSupportedVersions() {
        return ProtocolVersion.TLSv12.downTo(ProtocolVersion.TLSv10);
    }

    /* access modifiers changed from: protected */
    public boolean requireSRPServerExtension() {
        return false;
    }

    public ProtocolVersion getClientVersion() {
        return ProtocolVersion.TLSv12;
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsClient, com.mi.car.jsse.easysec.tls.TlsClient
    public Hashtable getClientExtensions() throws IOException {
        Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions());
        TlsSRPUtils.addSRPExtension(clientExtensions, this.srpIdentity.getSRPIdentity());
        return clientExtensions;
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsClient, com.mi.car.jsse.easysec.tls.TlsClient
    public void processServerExtensions(Hashtable serverExtensions) throws IOException {
        if (TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsSRPUtils.EXT_SRP, (short) 47) || !requireSRPServerExtension()) {
            super.processServerExtensions(serverExtensions);
            return;
        }
        throw new TlsFatalAlert((short) 47);
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsClient, com.mi.car.jsse.easysec.tls.TlsClient
    public TlsSRPIdentity getSRPIdentity() {
        return this.srpIdentity;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsClient
    public TlsAuthentication getAuthentication() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }
}
