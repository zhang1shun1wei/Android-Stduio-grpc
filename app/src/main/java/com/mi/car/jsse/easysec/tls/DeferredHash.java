package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import com.mi.car.jsse.easysec.util.Integers;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;

/* access modifiers changed from: package-private */
public class DeferredHash implements TlsHandshakeHash {
    protected static final int BUFFERING_HASH_LIMIT = 4;
    private DigestInputBuffer buf = new DigestInputBuffer();
    protected TlsContext context;
    private boolean forceBuffering = false;
    private Hashtable hashes = new Hashtable();
    private boolean sealed = false;

    DeferredHash(TlsContext context2) {
        this.context = context2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHandshakeHash
    public void copyBufferTo(OutputStream output) throws IOException {
        if (this.buf == null) {
            throw new IllegalStateException("Not buffering");
        }
        this.buf.copyInputTo(output);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHandshakeHash
    public void forceBuffering() {
        if (this.sealed) {
            throw new IllegalStateException("Too late to force buffering");
        }
        this.forceBuffering = true;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHandshakeHash
    public void notifyPRFDetermined() {
        SecurityParameters securityParameters = this.context.getSecurityParametersHandshake();
        switch (securityParameters.getPRFAlgorithm()) {
            case 0:
            case 1:
                checkTrackingHash(1);
                checkTrackingHash(2);
                return;
            default:
                checkTrackingHash(securityParameters.getPRFCryptoHashAlgorithm());
                return;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHandshakeHash
    public void trackHashAlgorithm(int cryptoHashAlgorithm) {
        if (this.sealed) {
            throw new IllegalStateException("Too late to track more hash algorithms");
        }
        checkTrackingHash(cryptoHashAlgorithm);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHandshakeHash
    public void sealHashAlgorithms() {
        if (this.sealed) {
            throw new IllegalStateException("Already sealed");
        }
        this.sealed = true;
        checkStopBuffering();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHandshakeHash
    public void stopTracking() {
        SecurityParameters securityParameters = this.context.getSecurityParametersHandshake();
        Hashtable newHashes = new Hashtable();
        switch (securityParameters.getPRFAlgorithm()) {
            case 0:
            case 1:
                cloneHash(newHashes, 1);
                cloneHash(newHashes, 2);
                break;
            default:
                cloneHash(newHashes, securityParameters.getPRFCryptoHashAlgorithm());
                break;
        }
        this.buf = null;
        this.hashes = newHashes;
        this.forceBuffering = false;
        this.sealed = true;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHandshakeHash
    public TlsHash forkPRFHash() {
        TlsHash prfHash;
        checkStopBuffering();
        SecurityParameters securityParameters = this.context.getSecurityParametersHandshake();
        switch (securityParameters.getPRFAlgorithm()) {
            case 0:
            case 1:
                prfHash = new CombinedHash(this.context, cloneHash(1), cloneHash(2));
                break;
            default:
                prfHash = cloneHash(securityParameters.getPRFCryptoHashAlgorithm());
                break;
        }
        if (this.buf != null) {
            this.buf.updateDigest(prfHash);
        }
        return prfHash;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHandshakeHash
    public byte[] getFinalHash(int cryptoHashAlgorithm) {
        TlsHash hash = (TlsHash) this.hashes.get(box(cryptoHashAlgorithm));
        if (hash == null) {
            throw new IllegalStateException("CryptoHashAlgorithm." + cryptoHashAlgorithm + " is not being tracked");
        }
        checkStopBuffering();
        TlsHash hash2 = hash.cloneHash();
        if (this.buf != null) {
            this.buf.updateDigest(hash2);
        }
        return hash2.calculateHash();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public void update(byte[] input, int inOff, int len) {
        if (this.buf != null) {
            this.buf.write(input, inOff, len);
            return;
        }
        Enumeration e = this.hashes.elements();
        while (e.hasMoreElements()) {
            ((TlsHash) e.nextElement()).update(input, inOff, len);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public byte[] calculateHash() {
        throw new IllegalStateException("Use 'forkPRFHash' to get a definite hash");
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public TlsHash cloneHash() {
        throw new IllegalStateException("attempt to clone a DeferredHash");
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public void reset() {
        if (this.buf != null) {
            this.buf.reset();
            return;
        }
        Enumeration e = this.hashes.elements();
        while (e.hasMoreElements()) {
            ((TlsHash) e.nextElement()).reset();
        }
    }

    /* access modifiers changed from: protected */
    public Integer box(int cryptoHashAlgorithm) {
        return Integers.valueOf(cryptoHashAlgorithm);
    }

    /* access modifiers changed from: protected */
    public void checkStopBuffering() {
        if (!this.forceBuffering && this.sealed && this.buf != null && this.hashes.size() <= 4) {
            Enumeration e = this.hashes.elements();
            while (e.hasMoreElements()) {
                this.buf.updateDigest((TlsHash) e.nextElement());
            }
            this.buf = null;
        }
    }

    /* access modifiers changed from: protected */
    public void checkTrackingHash(int cryptoHashAlgorithm) {
        checkTrackingHash(box(cryptoHashAlgorithm));
    }

    /* access modifiers changed from: protected */
    public void checkTrackingHash(Integer cryptoHashAlgorithm) {
        if (!this.hashes.containsKey(cryptoHashAlgorithm)) {
            this.hashes.put(cryptoHashAlgorithm, this.context.getCrypto().createHash(cryptoHashAlgorithm.intValue()));
        }
    }

    /* access modifiers changed from: protected */
    public TlsHash cloneHash(int cryptoHashAlgorithm) {
        return cloneHash(box(cryptoHashAlgorithm));
    }

    /* access modifiers changed from: protected */
    public TlsHash cloneHash(Integer cryptoHashAlgorithm) {
        return ((TlsHash) this.hashes.get(cryptoHashAlgorithm)).cloneHash();
    }

    /* access modifiers changed from: protected */
    public void cloneHash(Hashtable newHashes, int cryptoHashAlgorithm) {
        cloneHash(newHashes, box(cryptoHashAlgorithm));
    }

    /* access modifiers changed from: protected */
    public void cloneHash(Hashtable newHashes, Integer cryptoHashAlgorithm) {
        TlsHash hash = cloneHash(cryptoHashAlgorithm);
        if (this.buf != null) {
            this.buf.updateDigest(hash);
        }
        newHashes.put(cryptoHashAlgorithm, hash);
    }
}
