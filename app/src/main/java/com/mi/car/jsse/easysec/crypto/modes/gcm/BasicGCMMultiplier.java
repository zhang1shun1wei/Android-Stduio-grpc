package com.mi.car.jsse.easysec.crypto.modes.gcm;

public class BasicGCMMultiplier implements GCMMultiplier {
    private long[] H;

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] H2) {
        this.H = GCMUtil.asLongs(H2);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMMultiplier
    public void multiplyH(byte[] x) {
        GCMUtil.multiply(x, this.H);
    }
}
