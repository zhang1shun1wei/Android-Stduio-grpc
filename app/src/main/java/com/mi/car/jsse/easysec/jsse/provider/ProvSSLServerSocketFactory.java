package com.mi.car.jsse.easysec.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

class ProvSSLServerSocketFactory extends SSLServerSocketFactory {
    protected final ContextData contextData;

    ProvSSLServerSocketFactory(ContextData contextData2) {
        this.contextData = contextData2;
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket() throws IOException {
        return new ProvSSLServerSocket(this.contextData);
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket(int port) throws IOException {
        return new ProvSSLServerSocket(this.contextData, port);
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return new ProvSSLServerSocket(this.contextData, port, backlog);
    }

    @Override // javax.net.ServerSocketFactory
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        return new ProvSSLServerSocket(this.contextData, port, backlog, ifAddress);
    }

    public String[] getDefaultCipherSuites() {
        return this.contextData.getContext().getDefaultCipherSuites(false);
    }

    public String[] getSupportedCipherSuites() {
        return this.contextData.getContext().getSupportedCipherSuites();
    }
}
