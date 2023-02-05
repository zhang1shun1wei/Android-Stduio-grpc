package com.mi.car.jsse.easysec.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class SSLSocketFactoryImpl extends ProvSSLSocketFactory {
    @Override // javax.net.SocketFactory, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket() throws IOException {
        return super.createSocket();
    }

    @Override // javax.net.SocketFactory, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(String str, int i) throws IOException, UnknownHostException {
        return super.createSocket(str, i);
    }

    @Override // javax.net.SocketFactory, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(String str, int i, InetAddress inetAddress, int i2) throws IOException, UnknownHostException {
        return super.createSocket(str, i, inetAddress, i2);
    }

    @Override // javax.net.SocketFactory, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(InetAddress inetAddress, int i) throws IOException {
        return super.createSocket(inetAddress, i);
    }

    @Override // javax.net.SocketFactory, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress2, int i2) throws IOException {
        return super.createSocket(inetAddress, i, inetAddress2, i2);
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(Socket socket, InputStream inputStream, boolean z) throws IOException {
        return super.createSocket(socket, inputStream, z);
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketFactory, javax.net.ssl.SSLSocketFactory
    public /* bridge */ /* synthetic */ Socket createSocket(Socket socket, String str, int i, boolean z) throws IOException {
        return super.createSocket(socket, str, i, z);
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketFactory
    public /* bridge */ /* synthetic */ String[] getDefaultCipherSuites() {
        return super.getDefaultCipherSuites();
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketFactory
    public /* bridge */ /* synthetic */ String[] getSupportedCipherSuites() {
        return super.getSupportedCipherSuites();
    }

    public SSLSocketFactoryImpl() throws Exception {
        super(DefaultSSLContextSpi.getDefaultInstance().getContextData());
    }
}
