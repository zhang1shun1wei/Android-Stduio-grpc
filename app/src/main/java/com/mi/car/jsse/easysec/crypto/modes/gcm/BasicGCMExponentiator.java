package com.mi.car.jsse.easysec.crypto.modes.gcm;

public class BasicGCMExponentiator implements GCMExponentiator {
    private long[] x;

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMExponentiator
    public void init(byte[] x2) {
        this.x = GCMUtil.asLongs(x2);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMExponentiator
    public void exponentiateX(long pow, byte[] output) {
        long[] y = GCMUtil.oneAsLongs();
        if (pow > 0) {
            long[] powX = new long[2];
            GCMUtil.copy(this.x, powX);
            do {
                if ((1 & pow) != 0) {
                    GCMUtil.multiply(y, powX);
                }
                GCMUtil.square(powX, powX);
                pow >>>= 1;
            } while (pow > 0);
        }
        GCMUtil.asBytes(y, output);
    }
}
