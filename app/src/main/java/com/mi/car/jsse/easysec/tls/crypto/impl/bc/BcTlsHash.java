package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;

final class BcTlsHash implements TlsHash {
    private final BcTlsCrypto crypto;
    private final int cryptoHashAlgorithm;
    private final Digest digest;

    BcTlsHash(BcTlsCrypto crypto2, int cryptoHashAlgorithm2) {
        this(crypto2, cryptoHashAlgorithm2, crypto2.createDigest(cryptoHashAlgorithm2));
    }

    private BcTlsHash(BcTlsCrypto crypto2, int cryptoHashAlgorithm2, Digest digest2) {
        this.crypto = crypto2;
        this.cryptoHashAlgorithm = cryptoHashAlgorithm2;
        this.digest = digest2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public void update(byte[] data, int offSet, int length) {
        this.digest.update(data, offSet, length);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public byte[] calculateHash() {
        byte[] rv = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(rv, 0);
        return rv;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public TlsHash cloneHash() {
        return new BcTlsHash(this.crypto, this.cryptoHashAlgorithm, this.crypto.cloneDigest(this.cryptoHashAlgorithm, this.digest));
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHash
    public void reset() {
        this.digest.reset();
    }
}
