package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import java.io.IOException;

public abstract class AbstractTlsPeer implements TlsPeer {
    private volatile TlsCloseable closeHandle;
    private final TlsCrypto crypto;

    /* access modifiers changed from: protected */
    public abstract int[] getSupportedCipherSuites();

    protected AbstractTlsPeer(TlsCrypto crypto2) {
        this.crypto = crypto2;
    }

    /* access modifiers changed from: protected */
    public ProtocolVersion[] getSupportedVersions() {
        return ProtocolVersion.TLSv12.downTo(ProtocolVersion.TLSv10);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public void cancel() throws IOException {
        TlsCloseable closeHandle2 = this.closeHandle;
        if (closeHandle2 != null) {
            closeHandle2.close();
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public TlsCrypto getCrypto() {
        return this.crypto;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public void notifyCloseHandle(TlsCloseable closeHandle2) {
        this.closeHandle = closeHandle2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public void notifyHandshakeBeginning() throws IOException {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public int getHandshakeTimeoutMillis() {
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public boolean allowLegacyResumption() {
        return false;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public int getMaxCertificateChainLength() {
        return 10;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public int getMaxHandshakeMessageSize() {
        return 32768;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public short[] getPskKeyExchangeModes() {
        return new short[]{1};
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public boolean requiresCloseNotify() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public boolean requiresExtendedMasterSecret() {
        return false;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public boolean shouldCheckSigAlgOfPeerCerts() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public boolean shouldUseExtendedMasterSecret() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public boolean shouldUseExtendedPadding() {
        return false;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public boolean shouldUseGMTUnixTime() {
        return false;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException {
        if (!secureRenegotiation) {
            throw new TlsFatalAlert((short) 40);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public TlsKeyExchangeFactory getKeyExchangeFactory() throws IOException {
        return new DefaultTlsKeyExchangeFactory();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public void notifyAlertReceived(short alertLevel, short alertDescription) {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public void notifyHandshakeComplete() throws IOException {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public TlsHeartbeat getHeartbeat() {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public short getHeartbeatPolicy() {
        return 2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public int getRenegotiationPolicy() {
        return 0;
    }
}
