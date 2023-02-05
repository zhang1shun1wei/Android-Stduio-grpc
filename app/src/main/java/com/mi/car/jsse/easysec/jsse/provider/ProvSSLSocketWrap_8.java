package com.mi.car.jsse.easysec.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLSocket;

/* access modifiers changed from: package-private */
public class ProvSSLSocketWrap_8 extends ProvSSLSocketWrap {
    protected ProvSSLSocketWrap_8(ContextData contextData, Socket s, InputStream consumed, boolean autoClose) throws IOException {
        super(contextData, s, consumed, autoClose);
    }

    protected ProvSSLSocketWrap_8(ContextData contextData, Socket s, String host, int port, boolean autoClose) throws IOException {
        super(contextData, s, host, port, autoClose);
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
