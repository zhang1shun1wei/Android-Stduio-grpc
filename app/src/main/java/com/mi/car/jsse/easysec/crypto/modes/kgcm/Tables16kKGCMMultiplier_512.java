package com.mi.car.jsse.easysec.crypto.modes.kgcm;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import java.lang.reflect.Array;

public class Tables16kKGCMMultiplier_512 implements KGCMMultiplier {
    private long[][] T;

    @Override // com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier
    public void init(long[] H) {
        if (this.T == null) {
            this.T = (long[][]) Array.newInstance(Long.TYPE, 256, 8);
        } else if (KGCMUtil_512.equal(H, this.T[1])) {
            return;
        }
        KGCMUtil_512.copy(H, this.T[1]);
        for (int n = 2; n < 256; n += 2) {
            KGCMUtil_512.multiplyX(this.T[n >> 1], this.T[n]);
            KGCMUtil_512.add(this.T[n], this.T[1], this.T[n + 1]);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier
    public void multiplyH(long[] z) {
        long[] r = new long[8];
        KGCMUtil_512.copy(this.T[((int) (z[7] >>> 56)) & GF2Field.MASK], r);
        for (int i = 62; i >= 0; i--) {
            KGCMUtil_512.multiplyX8(r, r);
            KGCMUtil_512.add(this.T[((int) (z[i >>> 3] >>> ((i & 7) << 3))) & GF2Field.MASK], r, r);
        }
        KGCMUtil_512.copy(r, z);
    }
}
