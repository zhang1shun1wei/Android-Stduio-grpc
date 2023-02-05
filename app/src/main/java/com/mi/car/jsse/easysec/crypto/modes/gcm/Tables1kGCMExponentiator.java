package com.mi.car.jsse.easysec.crypto.modes.gcm;

import java.util.ArrayList;
import java.util.List;

public class Tables1kGCMExponentiator implements GCMExponentiator {
    private List lookupPowX2;

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMExponentiator
    public void init(byte[] x) {
        long[] y = GCMUtil.asLongs(x);
        if (this.lookupPowX2 == null || 0 == GCMUtil.areEqual(y, (long[]) this.lookupPowX2.get(0))) {
            this.lookupPowX2 = new ArrayList(8);
            this.lookupPowX2.add(y);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.gcm.GCMExponentiator
    public void exponentiateX(long pow, byte[] output) {
        long[] y = GCMUtil.oneAsLongs();
        int bit = 0;
        while (pow > 0) {
            if ((1 & pow) != 0) {
                GCMUtil.multiply(y, getPowX2(bit));
            }
            bit++;
            pow >>>= 1;
        }
        GCMUtil.asBytes(y, output);
    }

    private long[] getPowX2(int bit) {
        int last = this.lookupPowX2.size() - 1;
        if (last < bit) {
            long[] prev = (long[]) this.lookupPowX2.get(last);
            do {
                long[] next = new long[2];
                GCMUtil.square(prev, next);
                this.lookupPowX2.add(next);
                prev = next;
                last++;
            } while (last < bit);
        }
        return (long[]) this.lookupPowX2.get(bit);
    }
}
