package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCApplicationProtocolSelector;
import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import com.mi.car.jsse.easysec.jsse.BCSSLConnection;
import com.mi.car.jsse.easysec.jsse.BCSSLEngine;
import com.mi.car.jsse.easysec.jsse.BCSSLParameters;
import com.mi.car.jsse.easysec.jsse.BCX509Key;
import com.mi.car.jsse.easysec.tls.RecordPreview;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import com.mi.car.jsse.easysec.tls.TlsClientProtocol;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsProtocol;
import com.mi.car.jsse.easysec.tls.TlsServerProtocol;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/* access modifiers changed from: package-private */
public class ProvSSLEngine extends SSLEngine implements BCSSLEngine, ProvTlsManager {
    static final /* synthetic */ boolean $assertionsDisabled = (!ProvSSLEngine.class.desiredAssertionStatus());
    private static final Logger LOG = Logger.getLogger(ProvSSLEngine.class.getName());
    protected boolean closedEarly;
    protected ProvSSLConnection connection;
    protected final ContextData contextData;
    protected SSLException deferredException;
    protected boolean enableSessionCreation;
    protected ProvSSLSessionHandshake handshakeSession;
    protected SSLEngineResult.HandshakeStatus handshakeStatus;
    protected boolean initialHandshakeBegun;
    protected TlsProtocol protocol;
    protected ProvTlsPeer protocolPeer;
    protected final ProvSSLParameters sslParameters;
    protected boolean useClientMode;
    protected boolean useClientModeSet;

    protected ProvSSLEngine(ContextData contextData2) {
        this(contextData2, null, -1);
    }

    protected ProvSSLEngine(ContextData contextData2, String host, int port) {
        super(host, port);
        this.enableSessionCreation = true;
        this.useClientMode = true;
        this.useClientModeSet = false;
        this.closedEarly = false;
        this.initialHandshakeBegun = false;
        this.handshakeStatus = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        this.protocol = null;
        this.protocolPeer = null;
        this.connection = null;
        this.handshakeSession = null;
        this.deferredException = null;
        this.contextData = contextData2;
        this.sslParameters = contextData2.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public ContextData getContextData() {
        return this.contextData;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void beginHandshake() throws SSLException {
        if (!this.useClientModeSet) {
            throw new IllegalStateException("Client/Server mode must be set before the handshake can begin");
        } else if (this.closedEarly) {
            throw new SSLException("Connection is already closed");
        } else if (this.initialHandshakeBegun) {
            throw new UnsupportedOperationException("Renegotiation not supported");
        } else {
            this.initialHandshakeBegun = true;
            try {
                if (this.useClientMode) {
                    TlsClientProtocol clientProtocol = new TlsClientProtocol();
                    this.protocol = clientProtocol;
                    ProvTlsClient client = new ProvTlsClient(this, this.sslParameters);
                    this.protocolPeer = client;
                    clientProtocol.connect(client);
                    this.handshakeStatus = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                } else {
                    TlsServerProtocol serverProtocol = new TlsServerProtocol();
                    this.protocol = serverProtocol;
                    ProvTlsServer server = new ProvTlsServer(this, this.sslParameters);
                    this.protocolPeer = server;
                    serverProtocol.accept(server);
                    this.handshakeStatus = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                }
            } catch (SSLException e) {
                throw e;
            } catch (IOException e2) {
                throw new SSLException(e2);
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws IOException {
        try {
            this.contextData.getX509TrustManager().checkClientTrusted((X509Certificate[]) chain.clone(), authType, this);
        } catch (CertificateException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws IOException {
        try {
            this.contextData.getX509TrustManager().checkServerTrusted((X509Certificate[]) chain.clone(), authType, this);
        } catch (CertificateException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public BCX509Key chooseClientKey(String[] keyTypes, Principal[] issuers) {
        return getContextData().getX509KeyManager().chooseEngineClientKeyBC(keyTypes, (Principal[]) JsseUtils.clone(issuers), this);
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public BCX509Key chooseServerKey(String[] keyTypes, Principal[] issuers) {
        return getContextData().getX509KeyManager().chooseEngineServerKeyBC(keyTypes, (Principal[]) JsseUtils.clone(issuers), this);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void closeInbound() throws SSLException {
        if (!this.closedEarly) {
            if (this.protocol == null) {
                this.closedEarly = true;
            } else {
                try {
                    this.protocol.closeInput();
                } catch (IOException e) {
                    throw new SSLException(e);
                }
            }
        }
    }

    public synchronized void closeOutbound() {
        if (!this.closedEarly) {
            if (this.protocol == null) {
                this.closedEarly = true;
            } else {
                try {
                    this.protocol.close();
                } catch (IOException e) {
                    LOG.log(Level.WARNING, "Failed to close outbound", (Throwable) e);
                }
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLEngine
    public synchronized String getApplicationProtocol() {
        return this.connection == null ? null : this.connection.getApplicationProtocol();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLEngine
    public synchronized BCApplicationProtocolSelector<SSLEngine> getBCHandshakeApplicationProtocolSelector() {
        return this.sslParameters.getEngineAPSelector();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLEngine
    public synchronized BCExtendedSSLSession getBCHandshakeSession() {
        return this.handshakeSession;
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLEngine
    public BCExtendedSSLSession getBCSession() {
        return getSessionImpl();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLEngine
    public synchronized BCSSLConnection getConnection() {
        return this.connection;
    }

    public synchronized Runnable getDelegatedTask() {
        return null;
    }

    public synchronized String[] getEnabledCipherSuites() {
        return this.sslParameters.getCipherSuites();
    }

    public synchronized String[] getEnabledProtocols() {
        return this.sslParameters.getProtocols();
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public synchronized boolean getEnableSessionCreation() {
        return this.enableSessionCreation;
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLEngine
    public synchronized String getHandshakeApplicationProtocol() {
        return this.handshakeSession == null ? null : this.handshakeSession.getApplicationProtocol();
    }

    public synchronized SSLSession getHandshakeSession() {
        return this.handshakeSession == null ? null : this.handshakeSession.getExportSSLSession();
    }

    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return this.handshakeStatus;
    }

    public synchronized boolean getNeedClientAuth() {
        return this.sslParameters.getNeedClientAuth();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLEngine
    public synchronized BCSSLParameters getParameters() {
        return SSLParametersUtil.getParameters(this.sslParameters);
    }

    public SSLSession getSession() {
        return getSessionImpl().getExportSSLSession();
    }

    public synchronized SSLParameters getSSLParameters() {
        return SSLParametersUtil.getSSLParameters(this.sslParameters);
    }

    public synchronized String[] getSupportedCipherSuites() {
        return this.contextData.getContext().getSupportedCipherSuites();
    }

    public synchronized String[] getSupportedProtocols() {
        return this.contextData.getContext().getSupportedProtocols();
    }

    public synchronized boolean getUseClientMode() {
        return this.useClientMode;
    }

    public synchronized boolean getWantClientAuth() {
        return this.sslParameters.getWantClientAuth();
    }

    public synchronized boolean isInboundDone() {
        return this.closedEarly || (this.protocol != null && this.protocol.isClosed());
    }

    public synchronized boolean isOutboundDone() {
        boolean z = true;
        synchronized (this) {
            if (!this.closedEarly && (this.protocol == null || !this.protocol.isClosed() || this.protocol.getAvailableOutputBytes() >= 1)) {
                z = false;
            }
        }
        return z;
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLEngine
    public synchronized void setBCHandshakeApplicationProtocolSelector(BCApplicationProtocolSelector<SSLEngine> selector) {
        this.sslParameters.setEngineAPSelector(selector);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLEngine
    public synchronized void setBCSessionToResume(BCExtendedSSLSession session) {
        if (session == null) {
            throw new NullPointerException("'session' cannot be null");
        } else if (!(session instanceof ProvSSLSession)) {
            throw new IllegalArgumentException("Session-to-resume must be a session returned from 'getBCSession'");
        } else if (this.initialHandshakeBegun) {
            throw new IllegalArgumentException("Session-to-resume cannot be set after the handshake has begun");
        } else {
            this.sslParameters.setSessionToResume((ProvSSLSession) session);
        }
    }

    public synchronized void setEnabledCipherSuites(String[] suites) {
        this.sslParameters.setCipherSuites(suites);
    }

    public synchronized void setEnabledProtocols(String[] protocols) {
        this.sslParameters.setProtocols(protocols);
    }

    public synchronized void setEnableSessionCreation(boolean flag) {
        this.enableSessionCreation = flag;
    }

    public synchronized void setNeedClientAuth(boolean need) {
        this.sslParameters.setNeedClientAuth(need);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLEngine
    public synchronized void setParameters(BCSSLParameters parameters) {
        SSLParametersUtil.setParameters(this.sslParameters, parameters);
    }

    public synchronized void setSSLParameters(SSLParameters sslParameters2) {
        SSLParametersUtil.setSSLParameters(this.sslParameters, sslParameters2);
    }

    public synchronized void setUseClientMode(boolean useClientMode2) {
        if (this.initialHandshakeBegun) {
            throw new IllegalArgumentException("Client/Server mode cannot be changed after the handshake has begun");
        }
        if (this.useClientMode != useClientMode2) {
            this.contextData.getContext().updateDefaultSSLParameters(this.sslParameters, useClientMode2);
            this.useClientMode = useClientMode2;
        }
        this.useClientModeSet = true;
    }

    public synchronized void setWantClientAuth(boolean want) {
        this.sslParameters.setWantClientAuth(want);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
        SSLEngineResult sSLEngineResult;
        if (!this.initialHandshakeBegun) {
            beginHandshake();
        }
        SSLEngineResult.Status resultStatus = SSLEngineResult.Status.OK;
        int bytesConsumed = 0;
        int bytesProduced = 0;
        if (this.protocol.isClosed()) {
            resultStatus = SSLEngineResult.Status.CLOSED;
        } else {
            try {
                RecordPreview preview = getRecordPreview(src);
                if (preview == null || src.remaining() < preview.getRecordSize()) {
                    resultStatus = SSLEngineResult.Status.BUFFER_UNDERFLOW;
                } else if (hasInsufficientSpace(dsts, offset, length, preview.getContentLimit())) {
                    resultStatus = SSLEngineResult.Status.BUFFER_OVERFLOW;
                } else {
                    byte[] record = new byte[preview.getRecordSize()];
                    src.get(record);
                    this.protocol.offerInput(record, 0, record.length);
                    bytesConsumed = 0 + record.length;
                    int appDataAvailable = this.protocol.getAvailableInputBytes();
                    for (int dstIndex = 0; dstIndex < length && appDataAvailable > 0; dstIndex++) {
                        ByteBuffer dst = dsts[offset + dstIndex];
                        int count = Math.min(dst.remaining(), appDataAvailable);
                        if (count > 0) {
                            byte[] appData = new byte[count];
                            int numRead = this.protocol.readInput(appData, 0, count);
                            if ($assertionsDisabled || numRead == count) {
                                dst.put(appData);
                                bytesProduced += count;
                                appDataAvailable -= count;
                            } else {
                                throw new AssertionError();
                            }
                        }
                    }
                    if (appDataAvailable != 0) {
                        throw new TlsFatalAlert((short) 22);
                    }
                }
            } catch (IOException e) {
                if (this.handshakeStatus != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    throw new SSLException(e);
                }
                if (this.deferredException == null) {
                    this.deferredException = new SSLException(e);
                }
                this.handshakeStatus = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                sSLEngineResult = new SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_WRAP, 0, 0);
            }
        }
        SSLEngineResult.HandshakeStatus resultHandshakeStatus = this.handshakeStatus;
        if (this.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
            if (this.protocol.getAvailableOutputBytes() > 0) {
                this.handshakeStatus = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                resultHandshakeStatus = SSLEngineResult.HandshakeStatus.NEED_WRAP;
            } else if (this.protocolPeer.isHandshakeComplete()) {
                this.handshakeStatus = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = SSLEngineResult.HandshakeStatus.FINISHED;
            } else if (this.protocol.isClosed()) {
                this.handshakeStatus = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
            }
        }
        sSLEngineResult = new SSLEngineResult(resultStatus, resultHandshakeStatus, bytesConsumed, bytesProduced);
        return sSLEngineResult;
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
        SSLEngineResult.Status resultStatus;
        int bytesConsumed;
        int bytesProduced;
        SSLEngineResult.HandshakeStatus resultHandshakeStatus;
        if (this.deferredException != null) {
            SSLException e = this.deferredException;
            this.deferredException = null;
            throw e;
        }
        if (!this.initialHandshakeBegun) {
            beginHandshake();
        }
        resultStatus = SSLEngineResult.Status.OK;
        bytesConsumed = 0;
        bytesProduced = 0;
        if (this.handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            if (this.protocol.isClosed()) {
                resultStatus = SSLEngineResult.Status.CLOSED;
            } else if (this.protocol.getAvailableOutputBytes() <= 0) {
                try {
                    int srcRemaining = getTotalRemaining(srcs, offset, length, this.protocol.getApplicationDataLimit());
                    if (srcRemaining > 0) {
                        RecordPreview preview = this.protocol.previewOutputRecord(srcRemaining);
                        int srcLimit = preview.getContentLimit();
                        if (dst.remaining() < preview.getRecordSize()) {
                            resultStatus = SSLEngineResult.Status.BUFFER_OVERFLOW;
                        } else {
                            byte[] applicationData = new byte[srcLimit];
                            for (int srcIndex = 0; srcIndex < length && bytesConsumed < srcLimit; srcIndex++) {
                                ByteBuffer src = srcs[offset + srcIndex];
                                int count = Math.min(src.remaining(), srcLimit - bytesConsumed);
                                if (count > 0) {
                                    src.get(applicationData, bytesConsumed, count);
                                    bytesConsumed += count;
                                }
                            }
                            this.protocol.writeApplicationData(applicationData, 0, bytesConsumed);
                        }
                    }
                } catch (IOException e2) {
                    throw new SSLException(e2);
                }
            }
        }
        int outputAvailable = this.protocol.getAvailableOutputBytes();
        if (outputAvailable > 0) {
            int count2 = Math.min(dst.remaining(), outputAvailable);
            if (count2 > 0) {
                byte[] output = new byte[count2];
                int numRead = this.protocol.readOutput(output, 0, count2);
                if ($assertionsDisabled || numRead == count2) {
                    dst.put(output);
                    bytesProduced = 0 + count2;
                    outputAvailable -= count2;
                } else {
                    throw new AssertionError();
                }
            } else {
                resultStatus = SSLEngineResult.Status.BUFFER_OVERFLOW;
            }
        }
        resultHandshakeStatus = this.handshakeStatus;
        if (this.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP && outputAvailable <= 0) {
            if (this.protocolPeer.isHandshakeComplete()) {
                this.handshakeStatus = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = SSLEngineResult.HandshakeStatus.FINISHED;
            } else if (this.protocol.isClosed()) {
                this.handshakeStatus = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
            } else {
                this.handshakeStatus = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                resultHandshakeStatus = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
            }
        }
        return new SSLEngineResult(resultStatus, resultHandshakeStatus, bytesConsumed, bytesProduced);
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public String getPeerHost() {
        return super.getPeerHost();
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public String getPeerHostSNI() {
        return super.getPeerHost();
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public int getPeerPort() {
        return super.getPeerPort();
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public synchronized void notifyHandshakeComplete(ProvSSLConnection connection2) {
        if (this.handshakeSession != null) {
            if (!this.handshakeSession.isValid()) {
                connection2.getSession().invalidate();
            }
            this.handshakeSession.getJsseSecurityParameters().clear();
        }
        this.handshakeSession = null;
        this.connection = connection2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public synchronized void notifyHandshakeSession(ProvSSLSessionContext sslSessionContext, SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters, ProvSSLSession resumedSession) {
        String peerHost = getPeerHost();
        int peerPort = getPeerPort();
        if (resumedSession != null) {
            this.handshakeSession = new ProvSSLSessionResumed(sslSessionContext, peerHost, peerPort, securityParameters, jsseSecurityParameters, resumedSession.getTlsSession(), resumedSession.getJsseSessionParameters());
        } else {
            this.handshakeSession = new ProvSSLSessionHandshake(sslSessionContext, peerHost, peerPort, securityParameters, jsseSecurityParameters);
        }
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public synchronized String selectApplicationProtocol(List<String> protocols) {
        return this.sslParameters.getEngineAPSelector().select(this, protocols);
    }

    /* access modifiers changed from: package-private */
    public ProvSSLSession getSessionImpl() {
        return this.connection == null ? ProvSSLSession.NULL_SESSION : this.connection.getSession();
    }

    private RecordPreview getRecordPreview(ByteBuffer src) throws IOException {
        if (src.remaining() < 5) {
            return null;
        }
        byte[] recordHeader = new byte[5];
        int position = src.position();
        src.get(recordHeader);
        src.position(position);
        return this.protocol.previewInputRecord(recordHeader);
    }

    private int getTotalRemaining(ByteBuffer[] bufs, int off, int len, int limit) {
        int result = 0;
        for (int i = 0; i < len; i++) {
            int next = bufs[off + i].remaining();
            if (next >= limit - result) {
                return limit;
            }
            result += next;
        }
        return result;
    }

    private boolean hasInsufficientSpace(ByteBuffer[] dsts, int off, int len, int amount) {
        return getTotalRemaining(dsts, off, len, amount) < amount;
    }
}
