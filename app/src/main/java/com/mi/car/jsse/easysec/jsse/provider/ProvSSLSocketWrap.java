//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

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
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

class ProvSSLSocketWrap extends ProvSSLSocketBase implements ProvTlsManager {
    private static final Logger LOG = Logger.getLogger(ProvSSLSocketWrap.class.getName());
    protected final ProvSSLSocketWrap.AppDataInput appDataIn = new ProvSSLSocketWrap.AppDataInput();
    protected final ProvSSLSocketWrap.AppDataOutput appDataOut = new ProvSSLSocketWrap.AppDataOutput();
    protected final ContextData contextData;
    protected final Socket wrapSocket;
    protected final InputStream consumed;
    protected final boolean autoClose;
    protected final ProvSSLParameters sslParameters;
    protected String peerHost = null;
    protected String peerHostSNI = null;
    protected boolean enableSessionCreation = true;
    protected boolean useClientMode;
    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected ProvSSLConnection connection = null;
    protected ProvSSLSessionHandshake handshakeSession = null;

    private static Socket checkSocket(Socket s) throws SocketException {
        if (s == null) {
            throw new NullPointerException("'s' cannot be null");
        } else if (!s.isConnected()) {
            throw new SocketException("'s' is not a connected socket");
        } else {
            return s;
        }
    }

    protected ProvSSLSocketWrap(ContextData contextData, Socket s, InputStream consumed, boolean autoClose) throws IOException {
        this.contextData = contextData;
        this.wrapSocket = checkSocket(s);
        this.consumed = consumed;
        this.autoClose = autoClose;
        this.useClientMode = false;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(this.useClientMode);
        this.notifyConnected();
    }

    protected ProvSSLSocketWrap(ContextData contextData, Socket s, String host, int port, boolean autoClose) throws IOException {
        this.contextData = contextData;
        this.wrapSocket = checkSocket(s);
        this.consumed = null;
        this.peerHost = host;
        this.autoClose = autoClose;
        this.useClientMode = true;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(this.useClientMode);
        this.notifyConnected();
    }

    public ContextData getContextData() {
        return this.contextData;
    }

    public void bind(SocketAddress bindpoint) throws IOException {
        throw new SocketException("Wrapped socket should already be bound");
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws IOException {
        try {
            this.contextData.getX509TrustManager().checkClientTrusted((X509Certificate[])chain.clone(), authType, this);
        } catch (CertificateException var4) {
            throw new TlsFatalAlert((short)46, var4);
        }
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws IOException {
        try {
            this.contextData.getX509TrustManager().checkServerTrusted(chain.clone(), authType, this);
        } catch (CertificateException var4) {
            throw new TlsFatalAlert((short)46, var4);
        }
    }

    public BCX509Key chooseClientKey(String[] keyTypes, Principal[] issuers) {
        return this.getContextData().getX509KeyManager().chooseClientKeyBC(keyTypes, (Principal[])JsseUtils.clone(issuers), this);
    }

    public BCX509Key chooseServerKey(String[] keyTypes, Principal[] issuers) {
        return this.getContextData().getX509KeyManager().chooseServerKeyBC(keyTypes, (Principal[])JsseUtils.clone(issuers), this);
    }

    public synchronized void close() throws IOException {
        if (this.protocol == null) {
            this.closeSocket();
        } else {
            this.protocol.close();
        }

    }

    public void closeSocket() throws IOException {
        if (this.autoClose) {
            this.wrapSocket.close();
        } else if (this.protocol != null) {
        }

    }

    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        throw new SocketException("Wrapped socket should already be connected");
    }

    protected void finalize() throws Throwable {
        try {
            this.close();
        } catch (IOException var5) {
        } finally {
            super.finalize();
        }

    }

    public synchronized String getApplicationProtocol() {
        return null == this.connection ? null : this.connection.getApplicationProtocol();
    }

    public synchronized BCApplicationProtocolSelector<SSLSocket> getBCHandshakeApplicationProtocolSelector() {
        return this.sslParameters.getSocketAPSelector();
    }

    public synchronized BCExtendedSSLSession getBCHandshakeSession() {
        return this.handshakeSession;
    }

    public BCExtendedSSLSession getBCSession() {
        return this.getSessionImpl();
    }

    public SocketChannel getChannel() {
        return this.wrapSocket.getChannel();
    }

    public synchronized BCSSLConnection getConnection() {
        try {
            this.handshakeIfNecessary(false);
        } catch (Exception var2) {
            LOG.log(Level.FINE, "Failed to establish connection", var2);
        }

        return this.connection;
    }

    public synchronized String[] getEnabledCipherSuites() {
        return this.sslParameters.getCipherSuites();
    }

    public synchronized String[] getEnabledProtocols() {
        return this.sslParameters.getProtocols();
    }

    public synchronized boolean getEnableSessionCreation() {
        return this.enableSessionCreation;
    }

    public synchronized String getHandshakeApplicationProtocol() {
        return null == this.handshakeSession ? null : this.handshakeSession.getApplicationProtocol();
    }

    public synchronized SSLSession getHandshakeSession() {
        return null == this.handshakeSession ? null : this.handshakeSession.getExportSSLSession();
    }

    public InetAddress getInetAddress() {
        return this.wrapSocket.getInetAddress();
    }

    public InputStream getInputStream() throws IOException {
        return this.appDataIn;
    }

    public boolean getKeepAlive() throws SocketException {
        return this.wrapSocket.getKeepAlive();
    }

    public InetAddress getLocalAddress() {
        return this.wrapSocket.getLocalAddress();
    }

    public int getLocalPort() {
        return this.wrapSocket.getLocalPort();
    }

    public SocketAddress getLocalSocketAddress() {
        return this.wrapSocket.getLocalSocketAddress();
    }

    public synchronized boolean getNeedClientAuth() {
        return this.sslParameters.getNeedClientAuth();
    }

    public OutputStream getOutputStream() throws IOException {
        return this.appDataOut;
    }

    public int getPort() {
        return this.wrapSocket.getPort();
    }

    public int getReceiveBufferSize() throws SocketException {
        return this.wrapSocket.getReceiveBufferSize();
    }

    public SocketAddress getRemoteSocketAddress() {
        return this.wrapSocket.getRemoteSocketAddress();
    }

    public boolean getReuseAddress() throws SocketException {
        return this.wrapSocket.getReuseAddress();
    }

    public int getSendBufferSize() throws SocketException {
        return this.wrapSocket.getSendBufferSize();
    }

    public SSLSession getSession() {
        return this.getSessionImpl().getExportSSLSession();
    }

    public int getSoLinger() throws SocketException {
        return this.wrapSocket.getSoLinger();
    }

    public int getSoTimeout() throws SocketException {
        return this.wrapSocket.getSoTimeout();
    }

    public synchronized BCSSLParameters getParameters() {
        return SSLParametersUtil.getParameters(this.sslParameters);
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

    public boolean getTcpNoDelay() throws SocketException {
        return this.wrapSocket.getTcpNoDelay();
    }

    public int getTrafficClass() throws SocketException {
        return this.wrapSocket.getTrafficClass();
    }

    public synchronized boolean getUseClientMode() {
        return this.useClientMode;
    }

    public synchronized boolean getWantClientAuth() {
        return this.sslParameters.getWantClientAuth();
    }

    public boolean isBound() {
        return this.wrapSocket.isBound();
    }

    public boolean isConnected() {
        return this.wrapSocket.isConnected();
    }

    public synchronized boolean isClosed() {
        return this.protocol != null && this.protocol.isClosed();
    }

    public boolean isInputShutdown() {
        return this.wrapSocket.isInputShutdown();
    }

    public boolean isOutputShutdown() {
        return this.wrapSocket.isOutputShutdown();
    }

    public synchronized void setBCHandshakeApplicationProtocolSelector(BCApplicationProtocolSelector<SSLSocket> selector) {
        this.sslParameters.setSocketAPSelector(selector);
    }

    public synchronized void setBCSessionToResume(BCExtendedSSLSession session) {
        if (null == session) {
            throw new NullPointerException("'session' cannot be null");
        } else if (!(session instanceof ProvSSLSession)) {
            throw new IllegalArgumentException("Session-to-resume must be a session returned from 'getBCSession'");
        } else if (null != this.protocol) {
            throw new IllegalArgumentException("Session-to-resume cannot be set after the handshake has begun");
        } else {
            this.sslParameters.setSessionToResume((ProvSSLSession)session);
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

    public synchronized void setHost(String host) {
        this.peerHost = host;
        this.peerHostSNI = host;
    }

    public void setKeepAlive(boolean on) throws SocketException {
        this.wrapSocket.setKeepAlive(on);
    }

    public synchronized void setNeedClientAuth(boolean need) {
        this.sslParameters.setNeedClientAuth(need);
    }

    public synchronized void setParameters(BCSSLParameters parameters) {
        SSLParametersUtil.setParameters(this.sslParameters, parameters);
    }

    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        this.wrapSocket.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    public void setReceiveBufferSize(int size) throws SocketException {
        this.wrapSocket.setReceiveBufferSize(size);
    }

    public void setReuseAddress(boolean on) throws SocketException {
        this.wrapSocket.setReuseAddress(on);
    }

    public void setSendBufferSize(int size) throws SocketException {
        this.wrapSocket.setSendBufferSize(size);
    }

    public void setSoLinger(boolean on, int linger) throws SocketException {
        this.wrapSocket.setSoLinger(on, linger);
    }

    public void setSoTimeout(int timeout) throws SocketException {
        this.wrapSocket.setSoTimeout(timeout);
    }

    public synchronized void setSSLParameters(SSLParameters sslParameters) {
        SSLParametersUtil.setSSLParameters(this.sslParameters, sslParameters);
    }

    public void setTcpNoDelay(boolean on) throws SocketException {
        this.wrapSocket.setTcpNoDelay(on);
    }

    public void setTrafficClass(int tc) throws SocketException {
        this.wrapSocket.setTrafficClass(tc);
    }

    public synchronized void setUseClientMode(boolean useClientMode) {
        if (null != this.protocol) {
            throw new IllegalArgumentException("Mode cannot be changed after the initial handshake has begun");
        } else {
            if (this.useClientMode != useClientMode) {
                this.contextData.getContext().updateDefaultSSLParameters(this.sslParameters, useClientMode);
                this.useClientMode = useClientMode;
            }

        }
    }

    public synchronized void setWantClientAuth(boolean want) {
        this.sslParameters.setWantClientAuth(want);
    }

    public void shutdownInput() throws IOException {
        this.wrapSocket.shutdownInput();
    }

    public void shutdownOutput() throws IOException {
        this.wrapSocket.shutdownOutput();
    }

    public synchronized void startHandshake() throws IOException {
        this.startHandshake(true);
    }

    protected void startHandshake(boolean resumable) throws IOException {
        if (this.protocol == null) {
            InputStream input = this.wrapSocket.getInputStream();
            if (this.consumed != null) {
                input = new SequenceInputStream(this.consumed, (InputStream)input);
            }

            OutputStream output = this.wrapSocket.getOutputStream();
            if (this.useClientMode) {
                TlsClientProtocol clientProtocol = new ProvTlsClientProtocol((InputStream)input, output, this.socketCloser);
                clientProtocol.setResumableHandshake(resumable);
                this.protocol = clientProtocol;
                ProvTlsClient client = new ProvTlsClient(this, this.sslParameters);
                this.protocolPeer = client;
                clientProtocol.connect(client);
            } else {
                TlsServerProtocol serverProtocol = new ProvTlsServerProtocol((InputStream)input, output, this.socketCloser);
                serverProtocol.setResumableHandshake(resumable);
                this.protocol = serverProtocol;
                ProvTlsServer server = new ProvTlsServer(this, this.sslParameters);
                this.protocolPeer = server;
                serverProtocol.accept(server);
            }
        } else {
            if (!this.protocol.isHandshaking()) {
                throw new UnsupportedOperationException("Renegotiation not supported");
            }

            this.protocol.setResumableHandshake(resumable);
            this.protocol.resumeHandshake();
        }

    }

    public String toString() {
        return this.wrapSocket.toString();
    }

    public synchronized String getPeerHost() {
        return this.peerHost;
    }

    public synchronized String getPeerHostSNI() {
        return this.peerHostSNI;
    }

    public int getPeerPort() {
        return this.getPort();
    }

    public synchronized void notifyHandshakeComplete(ProvSSLConnection connection) {
        if (null != this.handshakeSession) {
            if (!this.handshakeSession.isValid()) {
                connection.getSession().invalidate();
            }

            this.handshakeSession.getJsseSecurityParameters().clear();
        }

        this.handshakeSession = null;
        this.connection = connection;
        this.notifyHandshakeCompletedListeners(connection.getSession().exportSSLSession);
    }

    public synchronized void notifyHandshakeSession(ProvSSLSessionContext sslSessionContext, SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters, ProvSSLSession resumedSession) {
        String peerHost = this.getPeerHost();
        int peerPort = this.getPeerPort();
        if (null != resumedSession) {
            this.handshakeSession = new ProvSSLSessionResumed(sslSessionContext, peerHost, peerPort, securityParameters, jsseSecurityParameters, resumedSession.getTlsSession(), resumedSession.getJsseSessionParameters());
        } else {
            this.handshakeSession = new ProvSSLSessionHandshake(sslSessionContext, peerHost, peerPort, securityParameters, jsseSecurityParameters);
        }

    }

    public synchronized String selectApplicationProtocol(List<String> protocols) {
        return this.sslParameters.getSocketAPSelector().select(this, protocols);
    }

    synchronized ProvSSLSession getSessionImpl() {
        this.getConnection();
        return null == this.connection ? ProvSSLSession.NULL_SESSION : this.connection.getSession();
    }

    synchronized void handshakeIfNecessary(boolean resumable) throws IOException {
        if (this.protocol == null || this.protocol.isHandshaking()) {
            this.startHandshake(resumable);
        }

    }

    synchronized void notifyConnected() {
        if (JsseUtils.isNameSpecified(this.peerHost)) {
            this.peerHostSNI = this.peerHost;
        } else {
            InetAddress peerAddress = this.getInetAddress();
            if (null != peerAddress) {
                if (this.useClientMode && provAssumeOriginalHostName) {
                    String originalHostName = peerAddress.getHostName();
                    this.peerHost = originalHostName;
                    this.peerHostSNI = originalHostName;
                } else {
                    if (this.useClientMode && provJdkTlsTrustNameService) {
                        this.peerHost = peerAddress.getHostName();
                    } else {
                        this.peerHost = peerAddress.getHostAddress();
                    }

                    this.peerHostSNI = null;
                }
            }
        }
    }

    class AppDataOutput extends OutputStream {
        AppDataOutput() {
        }

        public void close() throws IOException {
            ProvSSLSocketWrap.this.close();
        }

        public void write(int b) throws IOException {
            this.write(new byte[]{(byte)b}, 0, 1);
        }

        public void write(byte[] b, int off, int len) throws IOException {
            if (len > 0) {
                ProvSSLSocketWrap.this.handshakeIfNecessary(true);
                ProvSSLSocketWrap.this.protocol.writeApplicationData(b, off, len);
            }

        }
    }

    class AppDataInput extends InputStream {
        AppDataInput() {
        }

        public int available() throws IOException {
            synchronized(ProvSSLSocketWrap.this) {
                return ProvSSLSocketWrap.this.protocol == null ? 0 : ProvSSLSocketWrap.this.protocol.applicationDataAvailable();
            }
        }

        public void close() throws IOException {
            ProvSSLSocketWrap.this.close();
        }

        public int read() throws IOException {
            ProvSSLSocketWrap.this.handshakeIfNecessary(true);
            byte[] buf = new byte[1];
            int ret = ProvSSLSocketWrap.this.protocol.readApplicationData(buf, 0, 1);
            return ret < 0 ? -1 : buf[0] & 255;
        }

        public int read(byte[] b, int off, int len) throws IOException {
            if (len < 1) {
                return 0;
            } else {
                ProvSSLSocketWrap.this.handshakeIfNecessary(true);
                return ProvSSLSocketWrap.this.protocol.readApplicationData(b, off, len);
            }
        }
    }
}