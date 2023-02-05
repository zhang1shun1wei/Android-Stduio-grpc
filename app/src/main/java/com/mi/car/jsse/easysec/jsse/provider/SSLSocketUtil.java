package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import com.mi.car.jsse.easysec.jsse.BCSSLParameters;
import com.mi.car.jsse.easysec.jsse.BCSSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/* access modifiers changed from: package-private */
public abstract class SSLSocketUtil {
    private static final Method getHandshakeSession;
    private static final Method getSSLParameters;
    private static AtomicInteger threadNumber = new AtomicInteger();
    private static final boolean useSocket8;

    SSLSocketUtil() {
    }

    static {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLSocket");
        getHandshakeSession = ReflectionUtil.findMethod(methods, "getHandshakeSession");
        getSSLParameters = ReflectionUtil.findMethod(methods, "getSSLParameters");
        useSocket8 = ReflectionUtil.hasMethod(methods, "getApplicationProtocol");
    }

    static ProvSSLSocketDirect create(ContextData contextData, boolean enableSessionCreation, boolean useClientMode, ProvSSLParameters sslParameters) {
        return useSocket8 ? new ProvSSLSocketDirect_8(contextData, enableSessionCreation, useClientMode, sslParameters) : new ProvSSLSocketDirect(contextData, enableSessionCreation, useClientMode, sslParameters);
    }

    static ProvSSLSocketDirect create(ContextData contextData) {
        return useSocket8 ? new ProvSSLSocketDirect_8(contextData) : new ProvSSLSocketDirect(contextData);
    }

    static ProvSSLSocketDirect create(ContextData contextData, InetAddress address, int port, InetAddress clientAddress, int clientPort) throws IOException {
        return useSocket8 ? new ProvSSLSocketDirect_8(contextData, address, port, clientAddress, clientPort) : new ProvSSLSocketDirect(contextData, address, port, clientAddress, clientPort);
    }

    static ProvSSLSocketDirect create(ContextData contextData, InetAddress address, int port) throws IOException {
        return useSocket8 ? new ProvSSLSocketDirect_8(contextData, address, port) : new ProvSSLSocketDirect(contextData, address, port);
    }

    static ProvSSLSocketDirect create(ContextData contextData, String host, int port, InetAddress clientAddress, int clientPort) throws IOException, UnknownHostException {
        return useSocket8 ? new ProvSSLSocketDirect_8(contextData, host, port, clientAddress, clientPort) : new ProvSSLSocketDirect(contextData, host, port, clientAddress, clientPort);
    }

    static ProvSSLSocketDirect create(ContextData contextData, String host, int port) throws IOException, UnknownHostException {
        return useSocket8 ? new ProvSSLSocketDirect_8(contextData, host, port) : new ProvSSLSocketDirect(contextData, host, port);
    }

    static ProvSSLSocketWrap create(ContextData contextData, Socket s, InputStream consumed, boolean autoClose) throws IOException {
        return useSocket8 ? new ProvSSLSocketWrap_8(contextData, s, consumed, autoClose) : new ProvSSLSocketWrap(contextData, s, consumed, autoClose);
    }

    static ProvSSLSocketWrap create(ContextData contextData, Socket s, String host, int port, boolean autoClose) throws IOException {
        return useSocket8 ? new ProvSSLSocketWrap_8(contextData, s, host, port, autoClose) : new ProvSSLSocketWrap(contextData, s, host, port, autoClose);
    }

    static void handshakeCompleted(Runnable notifyRunnable) {
        new Thread(notifyRunnable, "BCJSSE-HandshakeCompleted-" + (threadNumber.getAndIncrement() & Integer.MAX_VALUE)).start();
    }

    static BCExtendedSSLSession importHandshakeSession(SSLSocket sslSocket) {
        SSLSession sslSession;
        if (sslSocket instanceof BCSSLSocket) {
            return ((BCSSLSocket) sslSocket).getBCHandshakeSession();
        }
        if (sslSocket == null || getHandshakeSession == null || (sslSession = (SSLSession) ReflectionUtil.invokeGetter(sslSocket, getHandshakeSession)) == null) {
            return null;
        }
        return SSLSessionUtil.importSSLSession(sslSession);
    }

    static BCSSLParameters importSSLParameters(SSLSocket sslSocket) {
        if (sslSocket instanceof BCSSLSocket) {
            return ((BCSSLSocket) sslSocket).getParameters();
        }
        if (sslSocket == null || getSSLParameters == null) {
            return null;
        }
        SSLParameters sslParameters = (SSLParameters) ReflectionUtil.invokeGetter(sslSocket, getSSLParameters);
        if (sslParameters != null) {
            return SSLParametersUtil.importSSLParameters(sslParameters);
        }
        throw new RuntimeException("SSLSocket.getSSLParameters returned null");
    }
}
