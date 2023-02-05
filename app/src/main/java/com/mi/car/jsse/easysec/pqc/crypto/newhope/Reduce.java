package com.mi.car.jsse.easysec.pqc.crypto.newhope;

/* access modifiers changed from: package-private */
public class Reduce {
    static final int QInv = 12287;
    static final int RLog = 18;
    static final int RMask = 262143;

    Reduce() {
    }

    static short montgomery(int a) {
        return (short) (((((a * QInv) & RMask) * 12289) + a) >>> 18);
    }

    static short barrett(short a) {
        int t = a & 65535;
        return (short) (t - (((t * 5) >>> 16) * 12289));
    }
}
