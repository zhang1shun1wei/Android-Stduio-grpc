package com.mi.car.jsse.easysec.crypto.modes.kgcm;

public class BasicKGCMMultiplier_256 implements KGCMMultiplier {
    private final long[] H = new long[4];

    @Override // com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] H2) {
        KGCMUtil_256.copy(H2, this.H);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] z) {
        KGCMUtil_256.multiply(z, this.H, z);
    }
}
