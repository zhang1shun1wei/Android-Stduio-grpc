package com.mi.car.jsse.easysec.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLSocket;

/* access modifiers changed from: package-private */
public class ProvSSLSocketDirect_8 extends ProvSSLSocketDirect {
    ProvSSLSocketDirect_8(ContextData contextData, boolean enableSessionCreation, boolean useClientMode, ProvSSLParameters sslParameters) {
        super(contextData, enableSessionCreation, useClientMode, sslParameters);
    }

    protected ProvSSLSocketDirect_8(ContextData contextData) {
        super(contextData);
    }

    protected ProvSSLSocketDirect_8(ContextData contextData, InetAddress address, int port, InetAddress clientAddress, int clientPort) throws IOException {
        super(contextData, address, port, clientAddress, clientPort);
    }

    protected ProvSSLSocketDirect_8(ContextData contextData, InetAddress address, int port) throws IOException {
        super(contextData, address, port);
    }

    protected ProvSSLSocketDirect_8(ContextData contextData, String host, int port, InetAddress clientAddress, int clientPort) throws IOException, UnknownHostException {
        super(contextData, host, port, clientAddress, clientPort);
    }

    protected ProvSSLSocketDirect_8(ContextData contextData, String host, int port) throws IOException, UnknownHostException {
        super(contextData, host, port);
    }

    @Override // javax.net.ssl.SSLSocket
    public synchronized void setHandshakeApplicationProtocolSelector(BiFunction<SSLSocket, List<String>, String> selector) {
        this.sslParameters.setSocketAPSelector(JsseUtils_8.importAPSelector(selector));
    }

    @Override // javax.net.ssl.SSLSocket
    public synchronized BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return JsseUtils_8.exportAPSelector(this.sslParameters.getSocketAPSelector());
    }
}
