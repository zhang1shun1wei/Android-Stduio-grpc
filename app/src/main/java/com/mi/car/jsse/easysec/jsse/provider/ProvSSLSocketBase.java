package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCSSLSocket;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/* access modifiers changed from: package-private */
public abstract class ProvSSLSocketBase extends SSLSocket implements BCSSLSocket {
    protected static final boolean provAssumeOriginalHostName = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.client.assumeOriginalHostName", false);
    protected static final boolean provJdkTlsTrustNameService = PropertyUtils.getBooleanSystemProperty("jdk.tls.trustNameService", false);
    protected final Map<HandshakeCompletedListener, AccessControlContext> listeners = Collections.synchronizedMap(new HashMap(4));
    protected final Closeable socketCloser = new Closeable() {
        /* class com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketBase.AnonymousClass1 */

        @Override // java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            ProvSSLSocketBase.this.closeSocket();
        }
    };

    protected ProvSSLSocketBase() {
    }

    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("'listener' cannot be null");
        }
        this.listeners.put(listener, AccessController.getContext());
    }

    /* access modifiers changed from: protected */
    public void closeSocket() throws IOException {
        super.close();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLSocket
    public void connect(String host, int port, int timeout) throws IOException {
        setHost(host);
        connect(createInetSocketAddress(host, port), timeout);
    }

    @Override // java.net.Socket
    public final boolean getOOBInline() throws SocketException {
        throw new SocketException("This method is ineffective, since sending urgent data is not supported by SSLSockets");
    }

    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("'listener' cannot be null");
        } else if (this.listeners.remove(listener) == null) {
            throw new IllegalArgumentException("'listener' is not registered");
        }
    }

    @Override // java.net.Socket
    public final void sendUrgentData(int data) throws IOException {
        throw new SocketException("This method is not supported by SSLSockets");
    }

    @Override // java.net.Socket
    public final void setOOBInline(boolean on) throws SocketException {
        throw new SocketException("This method is ineffective, since sending urgent data is not supported by SSLSockets");
    }

    /* access modifiers changed from: protected */
    public InetSocketAddress createInetSocketAddress(InetAddress address, int port) throws IOException {
        return new InetSocketAddress(address, port);
    }

    /* access modifiers changed from: protected */
    public InetSocketAddress createInetSocketAddress(String host, int port) throws IOException {
        return host == null ? new InetSocketAddress(InetAddress.getByName(null), port) : new InetSocketAddress(host, port);
    }

    /* access modifiers changed from: protected */
    public void implBind(InetAddress clientAddress, int clientPort) throws IOException {
        bind(createInetSocketAddress(clientAddress, clientPort));
    }

    /* access modifiers changed from: protected */
    public void implConnect(InetAddress address, int port) throws IOException {
        connect(createInetSocketAddress(address, port), 0);
    }

    /* access modifiers changed from: protected */
    public void implConnect(String host, int port) throws IOException, UnknownHostException {
        connect(createInetSocketAddress(host, port), 0);
    }

    /* access modifiers changed from: protected */
    public void notifyHandshakeCompletedListeners(SSLSession eventSession) {
        final Collection<Map.Entry<HandshakeCompletedListener, AccessControlContext>> entries = getHandshakeCompletedEntries();
        if (entries != null) {
            final HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, eventSession);
            SSLSocketUtil.handshakeCompleted(new Runnable() {
                /* class com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketBase.AnonymousClass2 */

                public void run() {
                    for (Map.Entry<HandshakeCompletedListener, AccessControlContext> entry : entries) {
                        final HandshakeCompletedListener listener = entry.getKey();
                        AccessController.doPrivileged(new PrivilegedAction<Void>() {
                            /* class com.mi.car.jsse.easysec.jsse.provider.ProvSSLSocketBase.AnonymousClass2.AnonymousClass1 */

                            @Override // java.security.PrivilegedAction
                            public Void run() {
                                listener.handshakeCompleted(event);
                                return null;
                            }
                        }, entry.getValue());
                    }
                }
            });
        }
    }

    private Collection<Map.Entry<HandshakeCompletedListener, AccessControlContext>> getHandshakeCompletedEntries() {
        ArrayList arrayList;
        synchronized (this.listeners) {
            if (this.listeners.isEmpty()) {
                arrayList = null;
            } else {
                arrayList = new ArrayList(this.listeners.entrySet());
            }
        }
        return arrayList;
    }
}
