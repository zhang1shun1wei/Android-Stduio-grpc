package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.util.Memoable;

public class GOST3411_2012_512Digest extends GOST3411_2012Digest {
    private static final byte[] IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    public GOST3411_2012_512Digest() {
        super(IV);
    }

    public GOST3411_2012_512Digest(GOST3411_2012_512Digest other) {
        super(IV);
        reset(other);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.GOST3411_2012Digest
    public String getAlgorithmName() {
        return "GOST3411-2012-512";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.GOST3411_2012Digest
    public int getDigestSize() {
        return 64;
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable, com.mi.car.jsse.easysec.crypto.digests.GOST3411_2012Digest
    public Memoable copy() {
        return new GOST3411_2012_512Digest(this);
    }
}
