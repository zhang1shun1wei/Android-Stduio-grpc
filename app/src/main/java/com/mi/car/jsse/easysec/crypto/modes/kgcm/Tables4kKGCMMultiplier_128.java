package com.mi.car.jsse.easysec.crypto.modes.kgcm;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import java.lang.reflect.Array;

public class Tables4kKGCMMultiplier_128 implements KGCMMultiplier {
    private long[][] T;

    @Override // com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] H) {
        if (this.T == null) {
            this.T = (long[][]) Array.newInstance(Long.TYPE, 256, 2);
        } else if (KGCMUtil_128.equal(H, this.T[1])) {
            return;
        }
        KGCMUtil_128.copy(H, this.T[1]);
        for (int n = 2; n < 256; n += 2) {
            KGCMUtil_128.multiplyX(this.T[n >> 1], this.T[n]);
            KGCMUtil_128.add(this.T[n], this.T[1], this.T[n + 1]);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] z) {
        long[] r = new long[2];
        KGCMUtil_128.copy(this.T[((int) (z[1] >>> 56)) & GF2Field.MASK], r);
        for (int i = 14; i >= 0; i--) {
            KGCMUtil_128.multiplyX8(r, r);
            KGCMUtil_128.add(this.T[((int) (z[i >>> 3] >>> ((i & 7) << 3))) & GF2Field.MASK], r, r);
        }
        KGCMUtil_128.copy(r, z);
    }
}
