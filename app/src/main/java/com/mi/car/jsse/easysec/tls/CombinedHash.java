package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import com.mi.car.jsse.easysec.util.Arrays;

public class CombinedHash implements TlsHash {
    protected TlsContext context;
    protected TlsCrypto crypto;
    protected TlsHash md5;
    protected TlsHash sha1;

    CombinedHash(TlsContext context2, TlsHash md52, TlsHash sha12) {
        this.context = context2;
        this.crypto = context2.getCrypto();
        this.md5 = md52;
        this.sha1 = sha12;
    }

    public CombinedHash(TlsCrypto crypto2) {
        this.crypto = crypto2;
        this.md5 = crypto2.createHash(1);
        this.sha1 = crypto2.createHash(2);
    }

    public CombinedHash(CombinedHash t) {
        this.context = t.context;
        this.crypto = t.crypto;
        this.md5 = t.md5.cloneHash();
        this.sha1 = t.sha1.cloneHash();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public void update(byte[] input, int inOff, int len) {
        this.md5.update(input, inOff, len);
        this.sha1.update(input, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public byte[] calculateHash() {
        if (this.context != null && TlsUtils.isSSL(this.context)) {
            SSL3Utils.completeCombinedHash(this.context, this.md5, this.sha1);
        }
        return Arrays.concatenate(this.md5.calculateHash(), this.sha1.calculateHash());
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public TlsHash cloneHash() {
        return new CombinedHash(this);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public void reset() {
        this.md5.reset();
        this.sha1.reset();
    }
}
