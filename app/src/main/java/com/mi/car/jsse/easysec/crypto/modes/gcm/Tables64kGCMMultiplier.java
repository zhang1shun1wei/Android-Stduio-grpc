package com.mi.car.jsse.easysec.crypto.modes.gcm;

import com.mi.car.jsse.easysec.util.Pack;
import java.lang.reflect.Array;

public class Tables64kGCMMultiplier implements GCMMultiplier {
    private byte[] H;
    private long[][][] T;

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMMultiplier
    public void init(byte[] H2) {
        if (this.T == null) {
            this.T = (long[][][]) Array.newInstance(Long.TYPE, 16, 256, 2);
        } else if (GCMUtil.areEqual(this.H, H2) != 0) {
            return;
        }
        this.H = new byte[16];
        GCMUtil.copy(H2, this.H);
        for (int i = 0; i < 16; i++) {
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
        long[] t00 = this.T[0][x[0] & 255];
        long[] t01 = this.T[1][x[1] & 255];
        long[] t02 = this.T[2][x[2] & 255];
        long[] t03 = this.T[3][x[3] & 255];
        long[] t04 = this.T[4][x[4] & 255];
        long[] t05 = this.T[5][x[5] & 255];
        long[] t06 = this.T[6][x[6] & 255];
        long[] t07 = this.T[7][x[7] & 255];
        long[] t08 = this.T[8][x[8] & 255];
        long[] t09 = this.T[9][x[9] & 255];
        long[] t10 = this.T[10][x[10] & 255];
        long[] t11 = this.T[11][x[11] & 255];
        long[] t12 = this.T[12][x[12] & 255];
        long[] t13 = this.T[13][x[13] & 255];
        long[] t14 = this.T[14][x[14] & 255];
        long[] t15 = this.T[15][x[15] & 255];
        Pack.longToBigEndian(((((((((((((((t00[0] ^ t01[0]) ^ t02[0]) ^ t03[0]) ^ t04[0]) ^ t05[0]) ^ t06[0]) ^ t07[0]) ^ t08[0]) ^ t09[0]) ^ t10[0]) ^ t11[0]) ^ t12[0]) ^ t13[0]) ^ t14[0]) ^ t15[0], x, 0);
        Pack.longToBigEndian(((((((((((((((t00[1] ^ t01[1]) ^ t02[1]) ^ t03[1]) ^ t04[1]) ^ t05[1]) ^ t06[1]) ^ t07[1]) ^ t08[1]) ^ t09[1]) ^ t10[1]) ^ t11[1]) ^ t12[1]) ^ t13[1]) ^ t14[1]) ^ t15[1], x, 8);
    }
}
