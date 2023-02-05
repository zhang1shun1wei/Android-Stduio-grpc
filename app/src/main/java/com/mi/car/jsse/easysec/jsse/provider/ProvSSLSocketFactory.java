package com.mi.car.jsse.easysec.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocketFactory;

class ProvSSLSocketFactory extends SSLSocketFactory {
    protected final ContextData contextData;

    ProvSSLSocketFactory(ContextData contextData2) {
        this.contextData = contextData2;
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket() throws IOException {
        return SSLSocketUtil.create(this.contextData);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return SSLSocketUtil.create(this.contextData, host, port);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return SSLSocketUtil.create(this.contextData, address, port, localAddress, localPort);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return SSLSocketUtil.create(this.contextData, host, port);
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        return SSLSocketUtil.create(this.contextData, host, port, localHost, localPort);
    }

    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException {
        return SSLSocketUtil.create(this.contextData, s, consumed, autoClose);
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return SSLSocketUtil.create(this.contextData, s, host, port, autoClose);
    }

    public String[] getDefaultCipherSuites() {
        return this.contextData.getContext().getDefaultCipherSuites(true);
    }

    public String[] getSupportedCipherSuites() {
        return this.contextData.getContext().getSupportedCipherSuites();
    }
}
