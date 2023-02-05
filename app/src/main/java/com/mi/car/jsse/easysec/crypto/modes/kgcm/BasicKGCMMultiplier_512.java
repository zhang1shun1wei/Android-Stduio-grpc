package com.mi.car.jsse.easysec.crypto.modes.kgcm;

public class BasicKGCMMultiplier_512 implements KGCMMultiplier {
    private final long[] H = new long[8];

    @Override // com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] H2) {
        KGCMUtil_512.copy(H2, this.H);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] z) {
        KGCMUtil_512.multiply(z, this.H, z);
    }
}
