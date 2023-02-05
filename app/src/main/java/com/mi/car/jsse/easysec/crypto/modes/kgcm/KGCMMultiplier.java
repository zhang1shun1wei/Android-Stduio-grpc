package com.mi.car.jsse.easysec.crypto.modes.kgcm;

public interface KGCMMultiplier {
    void init(long[] jArr);

    void multiplyH(long[] jArr);
}
