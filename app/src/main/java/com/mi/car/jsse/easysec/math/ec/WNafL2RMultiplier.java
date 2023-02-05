package com.mi.car.jsse.easysec.math.ec;

import com.mi.car.jsse.easysec.crypto.digests.Blake2xsDigest;
import com.mi.car.jsse.easysec.util.Integers;
import java.math.BigInteger;

public class WNafL2RMultiplier extends AbstractECMultiplier {
    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.AbstractECMultiplier
    public ECPoint multiplyPositive(ECPoint p, BigInteger k) {
        ECPoint[] table;
        ECPoint[] table2;
        ECPoint R;
        WNafPreCompInfo info = WNafUtil.precompute(p, WNafUtil.getWindowSize(k.bitLength()), true);
        ECPoint[] preComp = info.getPreComp();
        ECPoint[] preCompNeg = info.getPreCompNeg();
        int width = info.getWidth();
        int[] wnaf = WNafUtil.generateCompactWindowNaf(width, k);
        ECPoint R2 = p.getCurve().getInfinity();
        int i = wnaf.length;
        if (i > 1) {
            i--;
            int wi = wnaf[i];
            int digit = wi >> 16;
            int zeroes = wi & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH;
            int n = Math.abs(digit);
            if (digit < 0) {
                table2 = preCompNeg;
            } else {
                table2 = preComp;
            }
            if ((n << 2) < (1 << width)) {
                int highest = 32 - Integers.numberOfLeadingZeros(n);
                int scale = width - highest;
                R = table2[((1 << (width - 1)) - 1) >>> 1].add(table2[(((n ^ (1 << (highest - 1))) << scale) + 1) >>> 1]);
                zeroes -= scale;
            } else {
                R = table2[n >>> 1];
            }
            R2 = R.timesPow2(zeroes);
        }
        while (i > 0) {
            i--;
            int wi2 = wnaf[i];
            int digit2 = wi2 >> 16;
            int zeroes2 = wi2 & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH;
            int n2 = Math.abs(digit2);
            if (digit2 < 0) {
                table = preCompNeg;
            } else {
                table = preComp;
            }
            R2 = R2.twicePlus(table[n2 >>> 1]).timesPow2(zeroes2);
        }
        return R2;
    }
}
