package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.ExtendedDigest;

public class NonMemoableDigest implements ExtendedDigest {
    private ExtendedDigest baseDigest;

    public NonMemoableDigest(ExtendedDigest baseDigest2) {
        if (baseDigest2 == null) {
            throw new IllegalArgumentException("baseDigest must not be null");
        }
        this.baseDigest = baseDigest2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return this.baseDigest.getAlgorithmName();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.baseDigest.getDigestSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        this.baseDigest.update(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        this.baseDigest.update(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        return this.baseDigest.doFinal(out, outOff);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.baseDigest.reset();
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return this.baseDigest.getByteLength();
    }
}
