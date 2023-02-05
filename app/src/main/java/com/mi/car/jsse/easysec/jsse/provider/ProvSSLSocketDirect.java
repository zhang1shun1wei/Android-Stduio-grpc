package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCApplicationProtocolSelector;
import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import com.mi.car.jsse.easysec.jsse.BCSSLConnection;
import com.mi.car.jsse.easysec.jsse.BCSSLParameters;
import com.mi.car.jsse.easysec.jsse.BCX509Key;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import com.mi.car.jsse.easysec.tls.TlsClientProtocol;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsProtocol;
import com.mi.car.jsse.easysec.tls.TlsServerProtocol;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/* access modifiers changed from: package-private */
public class ProvSSLSocketDirect extends ProvSSLSocketBase implements ProvTlsManager {
    private static final Logger LOG = Logger.getLogger(ProvSSLSocketDirect.class.getName());
    protected final AppDataInput appDataIn = new AppDataInput();
    protected final AppDataOutput appDataOut = new AppDataOutput();
    protected ProvSSLConnection connection = null;
    protected final ContextData contextData;
    protected boolean enableSessionCreation = true;
    protected ProvSSLSessionHandshake handshakeSession = null;
    protected String peerHost = null;
    protected String peerHostSNI = null;
    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected final ProvSSLParameters sslParameters;
    protected boolean useClientMode = true;

    ProvSSLSocketDirect(ContextData contextData2, boolean enableSessionCreation2, boolean useClientMode2, ProvSSLParameters sslParameters2) {
        this.contextData = contextData2;
        this.enableSessionCreation = enableSessionCreation2;
        this.useClientMode = useClientMode2;
        this.sslParameters = sslParameters2;
    }

    protected ProvSSLSocketDirect(ContextData contextData2) {
        this.contextData = contextData2;
        this.sslParameters = contextData2.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    protected ProvSSLSocketDirect(ContextData contextData2, InetAddress address, int port, InetAddress clientAddress, int clientPort) throws IOException {
        this.contextData = contextData2;
        this.sslParameters = contextData2.getContext().getDefaultSSLParameters(this.useClientMode);
        implBind(clientAddress, clientPort);
        implConnect(address, port);
    }

    protected ProvSSLSocketDirect(ContextData contextData2, InetAddress address, int port) throws IOException {
        this.contextData = contextData2;
        this.sslParameters = contextData2.getContext().getDefaultSSLParameters(this.useClientMode);
        implConnect(address, port);
    }

    protected ProvSSLSocketDirect(ContextData contextData2, String host, int port, InetAddress clientAddress, int clientPort) throws IOException, UnknownHostException {
        this.contextData = contextData2;
        this.sslParameters = contextData2.getContext().getDefaultSSLParameters(this.useClientMode);
        this.peerHost = host;
        implBind(clientAddress, clientPort);
        implConnect(host, port);
    }

    protected ProvSSLSocketDirect(ContextData contextData2, String host, int port) throws IOException, UnknownHostException {
        this.contextData = contextData2;
        this.sslParameters = contextData2.getContext().getDefaultSSLParameters(this.useClientMode);
        this.peerHost = host;
        implConnect(host, port);
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public ContextData getContextData() {
        return this.contextData;
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
        return getContextData().getX509KeyManager().chooseClientKeyBC(keyTypes, (Principal[]) JsseUtils.clone(issuers), this);
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public BCX509Key chooseServerKey(String[] keyTypes, Principal[] issuers) {
        return getContextData().getX509KeyManager().chooseServerKeyBC(keyTypes, (Principal[]) JsseUtils.clone(issuers), this);
    }

    @Override // java.net.Socket, java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() throws IOException {
        if (this.protocol == null) {
            closeSocket();
        } else {
            this.protocol.close();
        }
    }

    @Override // java.net.Socket
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        if (!(endpoint instanceof InetSocketAddress)) {
            throw new SocketException("Only InetSocketAddress is supported.");
        }
        super.connect(endpoint, timeout);
        notifyConnected();
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:12:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:5:?, code lost:
        super.close();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x000f, code lost:
        r1 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x0010, code lost:
        super.finalize();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0013, code lost:
        throw r1;
     */
    /* JADX WARNING: Failed to process nested try/catch */
    /* JADX WARNING: Removed duplicated region for block: B:7:0x000f A[ExcHandler:  FINALLY, Splitter:B:0:0x0000] */
    @Override // java.lang.Object
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void finalize() throws Throwable {
        /*
            r2 = this;
            r2.close()     // Catch:{ IOException -> 0x0007, all -> 0x000f }
            super.finalize()
        L_0x0006:
            return
        L_0x0007:
            r0 = move-exception
            super.close()     // Catch:{ IOException -> 0x0014, all -> 0x000f }
        L_0x000b:
            super.finalize()
            goto L_0x0006
        L_0x000f:
            r1 = move-exception
            super.finalize()
            throw r1
        L_0x0014:
            r1 = move-exception
            goto L_0x000b
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketDirect.finalize():void");
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public synchronized String getApplicationProtocol() {
        return this.connection == null ? null : this.connection.getApplicationProtocol();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public synchronized BCApplicationProtocolSelector<SSLSocket> getBCHandshakeApplicationProtocolSelector() {
        return this.sslParameters.getSocketAPSelector();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public synchronized BCExtendedSSLSession getBCHandshakeSession() {
        return this.handshakeSession;
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public BCExtendedSSLSession getBCSession() {
        return getSessionImpl();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public synchronized BCSSLConnection getConnection() {
        try {
            handshakeIfNecessary(false);
        } catch (IOException e) {
            LOG.log(Level.FINE, "Failed to establish connection", (Throwable) e);
        }
        return this.connection;
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

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public synchronized String getHandshakeApplicationProtocol() {
        return this.handshakeSession == null ? null : this.handshakeSession.getApplicationProtocol();
    }

    public synchronized SSLSession getHandshakeSession() {
        return this.handshakeSession == null ? null : this.handshakeSession.getExportSSLSession();
    }

    @Override // java.net.Socket
    public InputStream getInputStream() throws IOException {
        return this.appDataIn;
    }

    public synchronized boolean getNeedClientAuth() {
        return this.sslParameters.getNeedClientAuth();
    }

    @Override // java.net.Socket
    public OutputStream getOutputStream() throws IOException {
        return this.appDataOut;
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
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

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public synchronized void setBCHandshakeApplicationProtocolSelector(BCApplicationProtocolSelector<SSLSocket> selector) {
        this.sslParameters.setSocketAPSelector(selector);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public synchronized void setBCSessionToResume(BCExtendedSSLSession session) {
        if (session == null) {
            throw new NullPointerException("'session' cannot be null");
        } else if (!(session instanceof ProvSSLSession)) {
            throw new IllegalArgumentException("Session-to-resume must be a session returned from 'getBCSession'");
        } else if (this.protocol != null) {
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

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public synchronized void setHost(String host) {
        this.peerHost = host;
        this.peerHostSNI = host;
    }

    public synchronized void setNeedClientAuth(boolean need) {
        this.sslParameters.setNeedClientAuth(need);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public synchronized void setParameters(BCSSLParameters parameters) {
        SSLParametersUtil.setParameters(this.sslParameters, parameters);
    }

    public synchronized void setSSLParameters(SSLParameters sslParameters2) {
        SSLParametersUtil.setSSLParameters(this.sslParameters, sslParameters2);
    }

    public synchronized void setUseClientMode(boolean useClientMode2) {
        if (this.protocol != null) {
            throw new IllegalArgumentException("Mode cannot be changed after the initial handshake has begun");
        } else if (this.useClientMode != useClientMode2) {
            this.contextData.getContext().updateDefaultSSLParameters(this.sslParameters, useClientMode2);
            this.useClientMode = useClientMode2;
        }
    }

    public synchronized void setWantClientAuth(boolean want) {
        this.sslParameters.setWantClientAuth(want);
    }

    @Override // java.net.Socket
    public void shutdownInput() throws IOException {
        throw new UnsupportedOperationException("shutdownInput() not supported in TLS");
    }

    @Override // java.net.Socket
    public void shutdownOutput() throws IOException {
        throw new UnsupportedOperationException("shutdownOutput() not supported in TLS");
    }

    @Override // javax.net.ssl.SSLSocket
    public synchronized void startHandshake() throws IOException {
        startHandshake(true);
    }

    /* access modifiers changed from: protected */
    public void startHandshake(boolean resumable) throws IOException {
        if (this.protocol == null) {
            InputStream input = super.getInputStream();
            OutputStream output = super.getOutputStream();
            if (this.useClientMode) {
                TlsClientProtocol clientProtocol = new ProvTlsClientProtocol(input, output, this.socketCloser);
                clientProtocol.setResumableHandshake(resumable);
                this.protocol = clientProtocol;
                ProvTlsClient client = new ProvTlsClient(this, this.sslParameters);
                this.protocolPeer = client;
                clientProtocol.connect(client);
                return;
            }
            TlsServerProtocol serverProtocol = new ProvTlsServerProtocol(input, output, this.socketCloser);
            serverProtocol.setResumableHandshake(resumable);
            this.protocol = serverProtocol;
            ProvTlsServer server = new ProvTlsServer(this, this.sslParameters);
            this.protocolPeer = server;
            serverProtocol.accept(server);
        } else if (this.protocol.isHandshaking()) {
            this.protocol.setResumableHandshake(resumable);
            this.protocol.resumeHandshake();
        } else {
            throw new UnsupportedOperationException("Renegotiation not supported");
        }
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public synchronized String getPeerHost() {
        return this.peerHost;
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public synchronized String getPeerHostSNI() {
        return this.peerHostSNI;
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public int getPeerPort() {
        return getPort();
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
        notifyHandshakeCompletedListeners(connection2.getSession().exportSSLSession);
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public synchronized void notifyHandshakeSession(ProvSSLSessionContext sslSessionContext, SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters, ProvSSLSession resumedSession) {
        String peerHost2 = getPeerHost();
        int peerPort = getPeerPort();
        if (resumedSession != null) {
            this.handshakeSession = new ProvSSLSessionResumed(sslSessionContext, peerHost2, peerPort, securityParameters, jsseSecurityParameters, resumedSession.getTlsSession(), resumedSession.getJsseSessionParameters());
        } else {
            this.handshakeSession = new ProvSSLSessionHandshake(sslSessionContext, peerHost2, peerPort, securityParameters, jsseSecurityParameters);
        }
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsManager
    public synchronized String selectApplicationProtocol(List<String> protocols) {
        return this.sslParameters.getSocketAPSelector().select(this, protocols);
    }

    /* access modifiers changed from: package-private */
    public synchronized ProvSSLSession getSessionImpl() {
        getConnection();
        return this.connection == null ? ProvSSLSession.NULL_SESSION : this.connection.getSession();
    }

    /* access modifiers changed from: package-private */
    public synchronized void handshakeIfNecessary(boolean resumable) throws IOException {
        if (this.protocol == null || this.protocol.isHandshaking()) {
            startHandshake(resumable);
        }
    }

    /* access modifiers changed from: package-private */
    public synchronized void notifyConnected() {
        if (JsseUtils.isNameSpecified(this.peerHost)) {
            this.peerHostSNI = this.peerHost;
        } else {
            InetAddress peerAddress = getInetAddress();
            if (peerAddress != null) {
                if (!this.useClientMode || !provAssumeOriginalHostName) {
                    if (!this.useClientMode || !provJdkTlsTrustNameService) {
                        this.peerHost = peerAddress.getHostAddress();
                    } else {
                        this.peerHost = peerAddress.getHostName();
                    }
                    this.peerHostSNI = null;
                } else {
                    String originalHostName = peerAddress.getHostName();
                    this.peerHost = originalHostName;
                    this.peerHostSNI = originalHostName;
                }
            }
        }
    }

    class AppDataInput extends InputStream {
        AppDataInput() {
        }

        @Override // java.io.InputStream
        public int read() throws IOException {
            byte[] buf = new byte[1];
            if (read(buf, 0, 1) <= 0) {
                return -1;
            }
            return buf[0] & 255;
        }

        @Override // java.io.InputStream
        public int read(byte[] b, int off, int len) throws IOException {
            if (len < 1) {
                return 0;
            }
            ProvSSLSocketDirect.this.handshakeIfNecessary(true);
            return ProvSSLSocketDirect.this.protocol.readApplicationData(b, off, len);
        }

        @Override // java.io.InputStream
        public int available() throws IOException {
            int applicationDataAvailable;
            synchronized (ProvSSLSocketDirect.this) {
                if (ProvSSLSocketDirect.this.protocol == null) {
                    applicationDataAvailable = 0;
                } else {
                    applicationDataAvailable = ProvSSLSocketDirect.this.protocol.applicationDataAvailable();
                }
            }
            return applicationDataAvailable;
        }

        @Override // java.io.Closeable, java.lang.AutoCloseable, java.io.InputStream
        public void close() throws IOException {
            ProvSSLSocketDirect.this.close();
        }
    }

    class AppDataOutput extends OutputStream {
        AppDataOutput() {
        }

        @Override // java.io.OutputStream
        public void write(int b) throws IOException {
            write(new byte[]{(byte) b}, 0, 1);
        }

        @Override // java.io.OutputStream
        public void write(byte[] b, int off, int len) throws IOException {
            if (len > 0) {
                ProvSSLSocketDirect.this.handshakeIfNecessary(true);
                ProvSSLSocketDirect.this.protocol.writeApplicationData(b, off, len);
            }
        }

        @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            ProvSSLSocketDirect.this.close();
        }
    }
}
