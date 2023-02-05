package com.mi.car.jsse.easysec.crypto.modes.kgcm;

public class BasicKGCMMultiplier_128 implements KGCMMultiplier {
    private final long[] H = new long[2];

    @Override // com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] H2) {
        KGCMUtil_128.copy(H2, this.H);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] z) {
        KGCMUtil_128.multiply(z, this.H, z);
    }
}
