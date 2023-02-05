package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import com.mi.car.jsse.easysec.jsse.BCSSLEngine;
import com.mi.car.jsse.easysec.jsse.BCSSLParameters;
import java.lang.reflect.Method;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/* access modifiers changed from: package-private */
public abstract class SSLEngineUtil {
    private static final Method getHandshakeSession;
    private static final Method getSSLParameters;
    private static final boolean useEngine8;

    SSLEngineUtil() {
    }

    static {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLEngine");
        getHandshakeSession = ReflectionUtil.findMethod(methods, "getHandshakeSession");
        getSSLParameters = ReflectionUtil.findMethod(methods, "getSSLParameters");
        useEngine8 = ReflectionUtil.hasMethod(methods, "getApplicationProtocol");
    }

    static SSLEngine create(ContextData contextData) {
        return useEngine8 ? new ProvSSLEngine_8(contextData) : new ProvSSLEngine(contextData);
    }

    static SSLEngine create(ContextData contextData, String host, int port) {
        return useEngine8 ? new ProvSSLEngine_8(contextData, host, port) : new ProvSSLEngine(contextData, host, port);
    }

    static BCExtendedSSLSession importHandshakeSession(SSLEngine sslEngine) {
        SSLSession sslSession;
        if (sslEngine instanceof BCSSLEngine) {
            return ((BCSSLEngine) sslEngine).getBCHandshakeSession();
        }
        if (sslEngine == null || getHandshakeSession == null || (sslSession = (SSLSession) ReflectionUtil.invokeGetter(sslEngine, getHandshakeSession)) == null) {
            return null;
        }
        return SSLSessionUtil.importSSLSession(sslSession);
    }

    static BCSSLParameters importSSLParameters(SSLEngine sslEngine) {
        if (sslEngine instanceof BCSSLEngine) {
            return ((BCSSLEngine) sslEngine).getParameters();
        }
        if (sslEngine == null || getSSLParameters == null) {
            return null;
        }
        SSLParameters sslParameters = (SSLParameters) ReflectionUtil.invokeGetter(sslEngine, getSSLParameters);
        if (sslParameters != null) {
            return SSLParametersUtil.importSSLParameters(sslParameters);
        }
        throw new RuntimeException("SSLEngine.getSSLParameters returned null");
    }
}
