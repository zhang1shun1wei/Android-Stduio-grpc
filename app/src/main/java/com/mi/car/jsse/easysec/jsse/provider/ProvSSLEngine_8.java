package com.mi.car.jsse.easysec.jsse.provider;

import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLEngine;

/* access modifiers changed from: package-private */
public class ProvSSLEngine_8 extends ProvSSLEngine {
    protected ProvSSLEngine_8(ContextData contextData) {
        super(contextData);
    }

    protected ProvSSLEngine_8(ContextData contextData, String host, int port) {
        super(contextData, host, port);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setHandshakeApplicationProtocolSelector(BiFunction<SSLEngine, List<String>, String> selector) {
        this.sslParameters.setEngineAPSelector(JsseUtils_8.importAPSelector(selector));
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return JsseUtils_8.exportAPSelector(this.sslParameters.getEngineAPSelector());
    }
}
