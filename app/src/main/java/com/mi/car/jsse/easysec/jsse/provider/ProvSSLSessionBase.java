package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCrypto;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLPermission;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.auth.x500.X500Principal;

/* access modifiers changed from: package-private */
public abstract class ProvSSLSessionBase extends BCExtendedSSLSession {
    protected final long creationTime;
    protected final JcaTlsCrypto crypto;
    protected final SSLSession exportSSLSession;
    protected final boolean isFips;
    protected final AtomicLong lastAccessedTime;
    protected final String peerHost;
    protected final int peerPort;
    protected final AtomicReference<ProvSSLSessionContext> sslSessionContext;
    protected final Map<String, Object> valueMap = Collections.synchronizedMap(new HashMap());

    /* access modifiers changed from: protected */
    public abstract int getCipherSuiteTLS();

    /* access modifiers changed from: protected */
    public abstract byte[] getIDArray();

    /* access modifiers changed from: protected */
    public abstract JsseSecurityParameters getJsseSecurityParameters();

    /* access modifiers changed from: protected */
    public abstract JsseSessionParameters getJsseSessionParameters();

    /* access modifiers changed from: protected */
    public abstract Certificate getLocalCertificateTLS();

    /* access modifiers changed from: protected */
    public abstract Certificate getPeerCertificateTLS();

    /* access modifiers changed from: protected */
    public abstract ProtocolVersion getProtocolTLS();

    /* access modifiers changed from: protected */
    public abstract void invalidateTLS();

    ProvSSLSessionBase(ProvSSLSessionContext sslSessionContext2, String peerHost2, int peerPort2) {
        this.sslSessionContext = new AtomicReference<>(sslSessionContext2);
        this.isFips = sslSessionContext2 == null ? false : sslSessionContext2.getSSLContext().isFips();
        this.crypto = sslSessionContext2 == null ? null : sslSessionContext2.getCrypto();
        this.peerHost = peerHost2;
        this.peerPort = peerPort2;
        this.creationTime = System.currentTimeMillis();
        this.exportSSLSession = SSLSessionUtil.exportSSLSession(this);
        this.lastAccessedTime = new AtomicLong(this.creationTime);
    }

    /* access modifiers changed from: package-private */
    public SSLSession getExportSSLSession() {
        return this.exportSSLSession;
    }

    /* access modifiers changed from: package-private */
    public void accessedAt(long accessTime) {
        long current = this.lastAccessedTime.get();
        if (accessTime > current) {
            this.lastAccessedTime.compareAndSet(current, accessTime);
        }
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ProvSSLSessionBase)) {
            return false;
        }
        return Arrays.areEqual(getIDArray(), ((ProvSSLSessionBase) obj).getIDArray());
    }

    public int getApplicationBufferSize() {
        return 16384;
    }

    public String getCipherSuite() {
        return ProvSSLContextSpi.getCipherSuiteName(getCipherSuiteTLS());
    }

    public long getCreationTime() {
        return this.creationTime;
    }

    public byte[] getId() {
        byte[] id = getIDArray();
        return TlsUtils.isNullOrEmpty(id) ? TlsUtils.EMPTY_BYTES : (byte[]) id.clone();
    }

    public long getLastAccessedTime() {
        return this.lastAccessedTime.get();
    }

    public java.security.cert.Certificate[] getLocalCertificates() {
        X509Certificate[] chain;
        if (this.crypto == null || (chain = JsseUtils.getX509CertificateChain(this.crypto, getLocalCertificateTLS())) == null || chain.length <= 0) {
            return null;
        }
        return chain;
    }

    public Principal getLocalPrincipal() {
        if (this.crypto != null) {
            return JsseUtils.getSubject(this.crypto, getLocalCertificateTLS());
        }
        return null;
    }

    public int getPacketBufferSize() {
        ProtocolVersion protocolVersion = getProtocolTLS();
        if (protocolVersion == null || !TlsUtils.isTLSv12(protocolVersion)) {
            return 18443;
        }
        if (TlsUtils.isTLSv13(protocolVersion)) {
            return 16911;
        }
        return 17413;
    }

    @Override // javax.net.ssl.SSLSession
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return OldCertUtil.getPeerCertificateChain(this);
    }

    @Override // javax.net.ssl.SSLSession
    public java.security.cert.Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        X509Certificate[] chain;
        if (this.crypto != null && (chain = JsseUtils.getX509CertificateChain(this.crypto, getPeerCertificateTLS())) != null && chain.length > 0) {
            return chain;
        }
        throw new SSLPeerUnverifiedException("No peer identity established");
    }

    @Override // javax.net.ssl.SSLSession
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        X500Principal principal;
        if (this.crypto != null && (principal = JsseUtils.getSubject(this.crypto, getPeerCertificateTLS())) != null) {
            return principal;
        }
        throw new SSLPeerUnverifiedException("No peer identity established");
    }

    public String getPeerHost() {
        return this.peerHost;
    }

    public int getPeerPort() {
        return this.peerPort;
    }

    public String getProtocol() {
        return ProvSSLContextSpi.getProtocolVersionName(getProtocolTLS());
    }

    public SSLSessionContext getSessionContext() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SSLPermission("getSSLSessionContext"));
        }
        return this.sslSessionContext.get();
    }

    public Object getValue(String name) {
        return this.valueMap.get(name);
    }

    public String[] getValueNames() {
        String[] strArr;
        synchronized (this.valueMap) {
            strArr = (String[]) this.valueMap.keySet().toArray(new String[this.valueMap.size()]);
        }
        return strArr;
    }

    public int hashCode() {
        return Arrays.hashCode(getIDArray());
    }

    public final void invalidate() {
        implInvalidate(true);
    }

    /* access modifiers changed from: package-private */
    public final void invalidatedBySessionContext() {
        implInvalidate(false);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession
    public boolean isFipsMode() {
        return this.isFips;
    }

    public boolean isValid() {
        if (this.sslSessionContext.get() != null && !TlsUtils.isNullOrEmpty(getIDArray())) {
            return true;
        }
        return false;
    }

    public void putValue(String name, Object value) {
        notifyUnbound(name, this.valueMap.put(name, value));
        notifyBound(name, value);
    }

    public void removeValue(String name) {
        notifyUnbound(name, this.valueMap.remove(name));
    }

    public String toString() {
        return "Session(" + getCreationTime() + "|" + getCipherSuite() + ")";
    }

    /* access modifiers changed from: protected */
    public void notifyBound(String name, Object value) {
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
        }
    }

    /* access modifiers changed from: protected */
    public void notifyUnbound(String name, Object value) {
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    private void implInvalidate(boolean removeFromSessionContext) {
        if (removeFromSessionContext) {
            ProvSSLSessionContext context = this.sslSessionContext.getAndSet(null);
            if (context != null) {
                context.removeSession(getIDArray());
            }
        } else {
            this.sslSessionContext.set(null);
        }
        invalidateTLS();
    }
}
