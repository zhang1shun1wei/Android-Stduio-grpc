package com.mi.car.jsse.easysec.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

public class SSLServerSocketFactoryImpl extends ProvSSLServerSocketFactory {
    @Override // javax.net.ServerSocketFactory, com.mi.car.jsse.easysec.jsse.provider.ProvSSLServerSocketFactory
    public /* bridge */ /* synthetic */ ServerSocket createServerSocket() throws IOException {
        return super.createServerSocket();
    }

    @Override // javax.net.ServerSocketFactory, com.mi.car.jsse.easysec.jsse.provider.ProvSSLServerSocketFactory
    public /* bridge */ /* synthetic */ ServerSocket createServerSocket(int i) throws IOException {
        return super.createServerSocket(i);
    }

    @Override // javax.net.ServerSocketFactory, com.mi.car.jsse.easysec.jsse.provider.ProvSSLServerSocketFactory
    public /* bridge */ /* synthetic */ ServerSocket createServerSocket(int i, int i2) throws IOException {
        return super.createServerSocket(i, i2);
    }

    @Override // javax.net.ServerSocketFactory, com.mi.car.jsse.easysec.jsse.provider.ProvSSLServerSocketFactory
    public /* bridge */ /* synthetic */ ServerSocket createServerSocket(int i, int i2, InetAddress inetAddress) throws IOException {
        return super.createServerSocket(i, i2, inetAddress);
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLServerSocketFactory
    public /* bridge */ /* synthetic */ String[] getDefaultCipherSuites() {
        return super.getDefaultCipherSuites();
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLServerSocketFactory
    public /* bridge */ /* synthetic */ String[] getSupportedCipherSuites() {
        return super.getSupportedCipherSuites();
    }

    public SSLServerSocketFactoryImpl() throws Exception {
        super(DefaultSSLContextSpi.getDefaultInstance().getContextData());
    }
}
