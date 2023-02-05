package com.mi.car.jsse.easysec.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

/* access modifiers changed from: package-private */
public class ProvSSLServerSocket extends SSLServerSocket {
    protected final ContextData contextData;
    protected boolean enableSessionCreation = true;
    protected final ProvSSLParameters sslParameters;
    protected boolean useClientMode = false;

    protected ProvSSLServerSocket(ContextData contextData2) throws IOException {
        this.contextData = contextData2;
        this.sslParameters = contextData2.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    protected ProvSSLServerSocket(ContextData contextData2, int port) throws IOException {
        super(port);
        this.contextData = contextData2;
        this.sslParameters = contextData2.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    protected ProvSSLServerSocket(ContextData contextData2, int port, int backlog) throws IOException {
        super(port, backlog);
        this.contextData = contextData2;
        this.sslParameters = contextData2.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    protected ProvSSLServerSocket(ContextData contextData2, int port, int backlog, InetAddress address) throws IOException {
        super(port, backlog, address);
        this.contextData = contextData2;
        this.sslParameters = contextData2.getContext().getDefaultSSLParameters(this.useClientMode);
    }

    @Override // java.net.ServerSocket
    public synchronized Socket accept() throws IOException {
        ProvSSLSocketDirect socket;
        socket = SSLSocketUtil.create(this.contextData, this.enableSessionCreation, this.useClientMode, this.sslParameters.copy());
        implAccept(socket);
        socket.notifyConnected();
        return socket;
    }

    public synchronized boolean getEnableSessionCreation() {
        return this.enableSessionCreation;
    }

    public synchronized String[] getEnabledCipherSuites() {
        return this.sslParameters.getCipherSuites();
    }

    public synchronized String[] getEnabledProtocols() {
        return this.sslParameters.getProtocols();
    }

    public synchronized boolean getNeedClientAuth() {
        return this.sslParameters.getNeedClientAuth();
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

    public synchronized void setEnableSessionCreation(boolean flag) {
        this.enableSessionCreation = flag;
    }

    public synchronized void setEnabledCipherSuites(String[] suites) {
        this.sslParameters.setCipherSuites(suites);
    }

    public synchronized void setEnabledProtocols(String[] protocols) {
        this.sslParameters.setProtocols(protocols);
    }

    public synchronized void setNeedClientAuth(boolean need) {
        this.sslParameters.setNeedClientAuth(need);
    }

    public synchronized void setSSLParameters(SSLParameters sslParameters2) {
        SSLParametersUtil.setSSLParameters(this.sslParameters, sslParameters2);
    }

    public synchronized void setUseClientMode(boolean useClientMode2) {
        if (this.useClientMode != useClientMode2) {
            this.contextData.getContext().updateDefaultSSLParameters(this.sslParameters, useClientMode2);
            this.useClientMode = useClientMode2;
        }
    }

    public synchronized void setWantClientAuth(boolean want) {
        this.sslParameters.setWantClientAuth(want);
    }
}
