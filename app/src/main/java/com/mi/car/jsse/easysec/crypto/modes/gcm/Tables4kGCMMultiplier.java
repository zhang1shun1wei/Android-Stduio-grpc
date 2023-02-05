package com.mi.car.jsse.easysec.crypto.modes.gcm;

import com.mi.car.jsse.easysec.util.Pack;
import java.lang.reflect.Array;

public class Tables4kGCMMultiplier implements GCMMultiplier {
    private byte[] H;
    private long[][] T;

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] H2) {
        if (this.T == null) {
            this.T = (long[][]) Array.newInstance(Long.TYPE, 256, 2);
        } else if (GCMUtil.areEqual(this.H, H2) != 0) {
            return;
        }
        this.H = new byte[16];
        GCMUtil.copy(H2, this.H);
        GCMUtil.asLongs(this.H, this.T[1]);
        GCMUtil.multiplyP7(this.T[1], this.T[1]);
        for (int n = 2; n < 256; n += 2) {
            GCMUtil.divideP(this.T[n >> 1], this.T[n]);
            GCMUtil.xor(this.T[n], this.T[1], this.T[n + 1]);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMMultiplier
    public void multiplyH(byte[] x) {
        long[] t = this.T[x[15] & 255];
        long z0 = t[0];
        long z1 = t[1];
        for (int i = 14; i >= 0; i--) {
            long[] t2 = this.T[x[i] & 255];
            long c = z1 << 56;
            z1 = t2[1] ^ ((z1 >>> 8) | (z0 << 56));
            z0 = ((((t2[0] ^ (z0 >>> 8)) ^ c) ^ (c >>> 1)) ^ (c >>> 2)) ^ (c >>> 7);
        }
        Pack.longToBigEndian(z0, x, 0);
        Pack.longToBigEndian(z1, x, 8);
    }
}
