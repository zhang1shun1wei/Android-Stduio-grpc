package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import com.mi.car.jsse.easysec.tls.crypto.TlsNonceGenerator;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;
import com.mi.car.jsse.easysec.util.Times;
import java.io.IOException;

/* access modifiers changed from: package-private */
public abstract class AbstractTlsContext implements TlsContext {
    private static long counter = Times.nanoTime();
    private ProtocolVersion[] clientSupportedVersions = null;
    private ProtocolVersion clientVersion = null;
    private int connectionEnd;
    private TlsCrypto crypto;
    private TlsNonceGenerator nonceGenerator;
    private ProtocolVersion rsaPreMasterSecretVersion = null;
    private SecurityParameters securityParametersConnection = null;
    private SecurityParameters securityParametersHandshake = null;
    private TlsSession session = null;
    private Object userObject = null;

    private static synchronized long nextCounterValue() {
        long j;
        synchronized (AbstractTlsContext.class) {
            j = counter + 1;
            counter = j;
        }
        return j;
    }

    private static TlsNonceGenerator createNonceGenerator(TlsCrypto crypto2, int connectionEnd2) {
        byte[] additionalSeedMaterial = new byte[16];
        Pack.longToBigEndian(nextCounterValue(), additionalSeedMaterial, 0);
        Pack.longToBigEndian(Times.nanoTime(), additionalSeedMaterial, 8);
        additionalSeedMaterial[0] = (byte) (additionalSeedMaterial[0] & Byte.MAX_VALUE);
        additionalSeedMaterial[0] = (byte) (additionalSeedMaterial[0] | ((byte) (connectionEnd2 << 7)));
        return crypto2.createNonceGenerator(additionalSeedMaterial);
    }

    AbstractTlsContext(TlsCrypto crypto2, int connectionEnd2) {
        this.crypto = crypto2;
        this.connectionEnd = connectionEnd2;
        this.nonceGenerator = createNonceGenerator(crypto2, connectionEnd2);
    }

    /* access modifiers changed from: package-private */
    public void handshakeBeginning(TlsPeer peer) throws IOException {
        synchronized (this) {
            if (this.securityParametersHandshake != null) {
                throw new TlsFatalAlert((short) 80, "Handshake already started");
            }
            this.securityParametersHandshake = new SecurityParameters();
            this.securityParametersHandshake.entity = this.connectionEnd;
            if (this.securityParametersConnection != null) {
                this.securityParametersHandshake.renegotiating = true;
                this.securityParametersHandshake.secureRenegotiation = this.securityParametersConnection.isSecureRenegotiation();
                this.securityParametersHandshake.negotiatedVersion = this.securityParametersConnection.getNegotiatedVersion();
            }
        }
        peer.notifyHandshakeBeginning();
    }

    /* access modifiers changed from: package-private */
    public void handshakeComplete(TlsPeer peer, TlsSession session2) throws IOException {
        synchronized (this) {
            if (this.securityParametersHandshake == null) {
                throw new TlsFatalAlert((short) 80);
            }
            this.session = session2;
            this.securityParametersConnection = this.securityParametersHandshake;
            this.securityParametersHandshake = null;
        }
        peer.notifyHandshakeComplete();
    }

    /* access modifiers changed from: package-private */
    public synchronized boolean isConnected() {
        return this.securityParametersConnection != null;
    }

    /* access modifiers changed from: package-private */
    public synchronized boolean isHandshaking() {
        return this.securityParametersHandshake != null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public TlsCrypto getCrypto() {
        return this.crypto;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public TlsNonceGenerator getNonceGenerator() {
        return this.nonceGenerator;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public synchronized SecurityParameters getSecurityParameters() {
        return this.securityParametersHandshake != null ? this.securityParametersHandshake : this.securityParametersConnection;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public synchronized SecurityParameters getSecurityParametersConnection() {
        return this.securityParametersConnection;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public synchronized SecurityParameters getSecurityParametersHandshake() {
        return this.securityParametersHandshake;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public ProtocolVersion[] getClientSupportedVersions() {
        return this.clientSupportedVersions;
    }

    /* access modifiers changed from: package-private */
    public void setClientSupportedVersions(ProtocolVersion[] clientSupportedVersions2) {
        this.clientSupportedVersions = clientSupportedVersions2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public ProtocolVersion getClientVersion() {
        return this.clientVersion;
    }

    /* access modifiers changed from: package-private */
    public void setClientVersion(ProtocolVersion clientVersion2) {
        this.clientVersion = clientVersion2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public ProtocolVersion getRSAPreMasterSecretVersion() {
        return this.rsaPreMasterSecretVersion;
    }

    /* access modifiers changed from: package-private */
    public void setRSAPreMasterSecretVersion(ProtocolVersion rsaPreMasterSecretVersion2) {
        this.rsaPreMasterSecretVersion = rsaPreMasterSecretVersion2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public ProtocolVersion getServerVersion() {
        return getSecurityParameters().getNegotiatedVersion();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public TlsSession getResumableSession() {
        TlsSession session2 = getSession();
        if (session2 == null || !session2.isResumable()) {
            return null;
        }
        return session2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public TlsSession getSession() {
        return this.session;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public Object getUserObject() {
        return this.userObject;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public void setUserObject(Object userObject2) {
        this.userObject = userObject2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public byte[] exportChannelBinding(int channelBinding) {
        SecurityParameters securityParameters = getSecurityParametersConnection();
        if (securityParameters == null) {
            throw new IllegalStateException("Export of channel bindings unavailable before handshake completion");
        } else if (TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion())) {
            return null;
        } else {
            switch (channelBinding) {
                case 0:
                    byte[] tlsServerEndPoint = securityParameters.getTLSServerEndPoint();
                    if (!TlsUtils.isNullOrEmpty(tlsServerEndPoint)) {
                        return Arrays.clone(tlsServerEndPoint);
                    }
                    return null;
                case 1:
                    return Arrays.clone(securityParameters.getTLSUnique());
                default:
                    throw new UnsupportedOperationException();
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public byte[] exportEarlyKeyingMaterial(String asciiLabel, byte[] context, int length) {
        SecurityParameters sp = getSecurityParametersHandshake();
        if (sp != null) {
            return exportKeyingMaterial13(checkEarlyExportSecret(sp.getEarlyExporterMasterSecret()), sp.getPRFCryptoHashAlgorithm(), asciiLabel, context, length);
        }
        throw new IllegalStateException("Export of early key material only available during handshake");
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public byte[] exportKeyingMaterial(String asciiLabel, byte[] context, int length) {
        SecurityParameters sp = getSecurityParametersConnection();
        if (sp == null) {
            throw new IllegalStateException("Export of key material unavailable before handshake completion");
        } else if (!sp.isExtendedMasterSecret()) {
            throw new IllegalStateException("Export of key material requires extended_master_secret");
        } else if (TlsUtils.isTLSv13(sp.getNegotiatedVersion())) {
            return exportKeyingMaterial13(checkExportSecret(sp.getExporterMasterSecret()), sp.getPRFCryptoHashAlgorithm(), asciiLabel, context, length);
        } else {
            return TlsUtils.PRF(sp, checkExportSecret(sp.getMasterSecret()), asciiLabel, TlsUtils.calculateExporterSeed(sp, context), length).extract();
        }
    }

    /* access modifiers changed from: protected */
    public byte[] exportKeyingMaterial13(TlsSecret secret, int cryptoHashAlgorithm, String asciiLabel, byte[] context, int length) {
        if (context == null) {
            context = TlsUtils.EMPTY_BYTES;
        } else if (!TlsUtils.isValidUint16(context.length)) {
            throw new IllegalArgumentException("'context' must have length less than 2^16 (or be null)");
        }
        try {
            TlsHash exporterHash = getCrypto().createHash(cryptoHashAlgorithm);
            byte[] emptyTranscriptHash = exporterHash.calculateHash();
            TlsSecret exporterSecret = TlsUtils.deriveSecret(getSecurityParametersConnection(), secret, asciiLabel, emptyTranscriptHash);
            byte[] exporterContext = emptyTranscriptHash;
            if (context.length > 0) {
                exporterHash.update(context, 0, context.length);
                exporterContext = exporterHash.calculateHash();
            }
            return TlsCryptoUtils.hkdfExpandLabel(exporterSecret, cryptoHashAlgorithm, "exporter", exporterContext, length).extract();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /* access modifiers changed from: protected */
    public TlsSecret checkEarlyExportSecret(TlsSecret secret) {
        if (secret != null) {
            return secret;
        }
        throw new IllegalStateException("Export of early key material not available for this handshake");
    }

    /* access modifiers changed from: protected */
    public TlsSecret checkExportSecret(TlsSecret secret) {
        if (secret != null) {
            return secret;
        }
        throw new IllegalStateException("Export of key material only available from notifyHandshakeComplete()");
    }
}
