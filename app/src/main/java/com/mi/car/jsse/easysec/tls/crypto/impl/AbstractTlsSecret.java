package com.mi.car.jsse.easysec.tls.crypto.impl;

import com.mi.car.jsse.easysec.tls.crypto.TlsEncryptor;
import com.mi.car.jsse.easysec.tls.crypto.TlsHMAC;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public abstract class AbstractTlsSecret implements TlsSecret {
    protected byte[] data;

    /* access modifiers changed from: protected */
    public abstract AbstractTlsCrypto getCrypto();

    protected static byte[] copyData(AbstractTlsSecret other) {
        return other.copyData();
    }

    protected AbstractTlsSecret(byte[] data2) {
        this.data = data2;
    }

    /* access modifiers changed from: protected */
    public void checkAlive() {
        if (this.data == null) {
            throw new IllegalStateException("Secret has already been extracted or destroyed");
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSecret
    public synchronized byte[] calculateHMAC(int cryptoHashAlgorithm, byte[] buf, int off, int len) {
        TlsHMAC hmac;
        checkAlive();
        hmac = getCrypto().createHMACForHash(cryptoHashAlgorithm);
        hmac.setKey(this.data, 0, this.data.length);
        hmac.update(buf, off, len);
        return hmac.calculateMAC();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSecret
    public synchronized void destroy() {
        if (this.data != null) {
            Arrays.fill(this.data, (byte) 0);
            this.data = null;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSecret
    public synchronized byte[] encrypt(TlsEncryptor encryptor) throws IOException {
        checkAlive();
        return encryptor.encrypt(this.data, 0, this.data.length);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSecret
    public synchronized byte[] extract() {
        byte[] result;
        checkAlive();
        result = this.data;
        this.data = null;
        return result;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSecret
    public synchronized boolean isAlive() {
        return this.data != null;
    }

    /* access modifiers changed from: package-private */
    public synchronized byte[] copyData() {
        return Arrays.clone(this.data);
    }
}
