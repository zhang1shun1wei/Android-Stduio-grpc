package com.mi.car.jsse.easysec.crypto.modes.gcm;

import com.mi.car.jsse.easysec.util.Pack;
import java.lang.reflect.Array;

public class Tables8kGCMMultiplier implements GCMMultiplier {
    private byte[] H;
    private long[][][] T;

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] H2) {
        if (this.T == null) {
            this.T = (long[][][]) Array.newInstance(Long.TYPE, 2, 256, 2);
        } else if (GCMUtil.areEqual(this.H, H2) != 0) {
            return;
        }
        this.H = new byte[16];
        GCMUtil.copy(H2, this.H);
        for (int i = 0; i < 2; i++) {
            long[][] t = this.T[i];
            if (i == 0) {
                GCMUtil.asLongs(this.H, t[1]);
                GCMUtil.multiplyP7(t[1], t[1]);
            } else {
                GCMUtil.multiplyP8(this.T[i - 1][1], t[1]);
            }
            for (int n = 2; n < 256; n += 2) {
                GCMUtil.divideP(t[n >> 1], t[n]);
                GCMUtil.xor(t[n], t[1], t[n + 1]);
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMMultiplier
    public void multiplyH(byte[] x) {
        long[][] T0 = this.T[0];
        long[][] T1 = this.T[1];
        long[] u = T0[x[14] & 255];
        long[] v = T1[x[15] & 255];
        long z0 = u[0] ^ v[0];
        long z1 = u[1] ^ v[1];
        for (int i = 12; i >= 0; i -= 2) {
            long[] u2 = T0[x[i] & 255];
            long[] v2 = T1[x[i + 1] & 255];
            long c = z1 << 48;
            z1 = (u2[1] ^ v2[1]) ^ ((z1 >>> 16) | (z0 << 48));
            z0 = (((((u2[0] ^ v2[0]) ^ (z0 >>> 16)) ^ c) ^ (c >>> 1)) ^ (c >>> 2)) ^ (c >>> 7);
        }
        Pack.longToBigEndian(z0, x, 0);
        Pack.longToBigEndian(z1, x, 8);
    }
}
