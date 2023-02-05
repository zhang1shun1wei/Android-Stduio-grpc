package com.mi.car.jsse.easysec.jsse.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocketFactory;

public class CustomSSLSocketFactory extends SSLSocketFactory {
    protected final SSLSocketFactory delegate;

    public CustomSSLSocketFactory(SSLSocketFactory delegate2) {
        if (delegate2 == null) {
            throw new NullPointerException("'delegate' cannot be null");
        }
        this.delegate = delegate2;
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket() throws IOException {
        return configureSocket(this.delegate.createSocket());
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return configureSocket(this.delegate.createSocket(host, port));
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return configureSocket(this.delegate.createSocket(address, port, localAddress, localPort));
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return configureSocket(this.delegate.createSocket(host, port));
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        return configureSocket(this.delegate.createSocket(host, port, localHost, localPort));
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return configureSocket(this.delegate.createSocket(s, host, port, autoClose));
    }

    public String[] getDefaultCipherSuites() {
        return this.delegate.getDefaultCipherSuites();
    }

    public String[] getSupportedCipherSuites() {
        return this.delegate.getSupportedCipherSuites();
    }

    /* access modifiers changed from: protected */
    public Socket configureSocket(Socket s) {
        return s;
    }
}
