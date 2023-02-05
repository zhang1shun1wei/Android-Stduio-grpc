package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.util.Memoable;

public final class GOST3411_2012_256Digest extends GOST3411_2012Digest {
    private static final byte[] IV = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    public GOST3411_2012_256Digest() {
        super(IV);
    }

    public GOST3411_2012_256Digest(GOST3411_2012_256Digest other) {
        super(IV);
        reset(other);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.GOST3411_2012Digest
    public String getAlgorithmName() {
        return "GOST3411-2012-256";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.GOST3411_2012Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.GOST3411_2012Digest
    public int doFinal(byte[] out, int outOff) {
        byte[] result = new byte[64];
        super.doFinal(result, 0);
        System.arraycopy(result, 32, out, outOff, 32);
        return 32;
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable, com.mi.car.jsse.easysec.crypto.digests.GOST3411_2012Digest
    public Memoable copy() {
        return new GOST3411_2012_256Digest(this);
    }
}
