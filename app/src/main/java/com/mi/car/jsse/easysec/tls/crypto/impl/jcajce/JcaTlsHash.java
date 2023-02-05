package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import java.security.MessageDigest;

public class JcaTlsHash implements TlsHash {
    private final MessageDigest digest;

    public JcaTlsHash(MessageDigest digest2) {
        this.digest = digest2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public void update(byte[] data, int offSet, int length) {
        this.digest.update(data, offSet, length);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public byte[] calculateHash() {
        return this.digest.digest();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public TlsHash cloneHash() {
        try {
            return new JcaTlsHash((MessageDigest) this.digest.clone());
        } catch (CloneNotSupportedException e) {
            throw new UnsupportedOperationException("unable to clone digest");
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public void reset() {
        this.digest.reset();
    }
}
