package com.mi.car.jsse.easysec.jsse.util;

import com.mi.car.jsse.easysec.jsse.BCSNIHostName;
import com.mi.car.jsse.easysec.jsse.BCSSLParameters;
import com.mi.car.jsse.easysec.jsse.BCSSLSocket;
import java.net.Socket;
import java.net.URL;
import java.util.Collections;
import java.util.concurrent.Callable;
import java.util.logging.Logger;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class SNISocketFactory extends CustomSSLSocketFactory {
    private static final Logger LOG = Logger.getLogger(SNISocketFactory.class.getName());
    protected static final ThreadLocal<SNISocketFactory> threadLocal = new ThreadLocal<>();
    protected final URL url;

    public static SocketFactory getDefault() {
        SSLSocketFactory sslSocketFactory = threadLocal.get();
        return sslSocketFactory != null ? sslSocketFactory : SSLSocketFactory.getDefault();
    }

    public SNISocketFactory(SSLSocketFactory delegate, URL url2) {
        super(delegate);
        this.url = url2;
    }

    public <V> V call(Callable<V> callable) throws Exception {
        try {
            threadLocal.set(this);
            return callable.call();
        } finally {
            threadLocal.remove();
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.util.CustomSSLSocketFactory
    public Socket configureSocket(Socket s) {
        if (s instanceof BCSSLSocket) {
            BCSSLSocket ssl = (BCSSLSocket) s;
            BCSNIHostName sniHostName = getBCSNIHostName();
            if (sniHostName != null) {
                LOG.fine("Setting SNI on socket: " + sniHostName);
                BCSSLParameters sslParameters = new BCSSLParameters();
                sslParameters.setServerNames(Collections.singletonList(sniHostName));
                ssl.setParameters(sslParameters);
            }
        }
        return s;
    }

    /* access modifiers changed from: protected */
    public BCSNIHostName getBCSNIHostName() {
        return SNIUtil.getBCSNIHostName(this.url);
    }
}
