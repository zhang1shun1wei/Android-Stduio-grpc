package com.mi.car.jsse.easysec.math.ec;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import java.math.BigInteger;

public class WTauNafMultiplier extends AbstractECMultiplier {
    static final String PRECOMP_NAME = "bc_wtnaf";

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.AbstractECMultiplier
    public ECPoint multiplyPositive(ECPoint point, BigInteger k) {
        if (!(point instanceof ECPoint.AbstractF2m)) {
            throw new IllegalArgumentException("Only ECPoint.AbstractF2m can be used in WTauNafMultiplier");
        }
        ECPoint.AbstractF2m p = (ECPoint.AbstractF2m) point;
        ECCurve.AbstractF2m curve = (ECCurve.AbstractF2m) p.getCurve();
        int m = curve.getFieldSize();
        byte a = curve.getA().toBigInteger().byteValue();
        byte mu = Tnaf.getMu(a);
        return multiplyWTnaf(p, Tnaf.partModReduction(k, m, a, curve.getSi(), mu, (byte) 10), a, mu);
    }

    private ECPoint.AbstractF2m multiplyWTnaf(ECPoint.AbstractF2m p, ZTauElement lambda, byte a, byte mu) {
        return multiplyFromWTnaf(p, Tnaf.tauAdicWNaf(mu, lambda, (byte) 4, BigInteger.valueOf(16), Tnaf.getTw(mu, 4), a == 0 ? Tnaf.alpha0 : Tnaf.alpha1));
    }

    private static ECPoint.AbstractF2m multiplyFromWTnaf(final ECPoint.AbstractF2m p, byte[] u) {
        ECCurve.AbstractF2m curve = (ECCurve.AbstractF2m) p.getCurve();
        final byte a = curve.getA().toBigInteger().byteValue();
        ECPoint.AbstractF2m[] pu = ((WTauNafPreCompInfo) curve.precompute(p, PRECOMP_NAME, new PreCompCallback() {
            /* class com.mi.car.jsse.easysec.math.ec.WTauNafMultiplier.AnonymousClass1 */

            @Override // com.mi.car.jsse.easysec.math.ec.PreCompCallback
            public PreCompInfo precompute(PreCompInfo existing) {
                if (existing instanceof WTauNafPreCompInfo) {
                    return existing;
                }
                WTauNafPreCompInfo result = new WTauNafPreCompInfo();
                result.setPreComp(Tnaf.getPreComp(p, a));
                return result;
            }
        })).getPreComp();
        ECPoint.AbstractF2m[] puNeg = new ECPoint.AbstractF2m[pu.length];
        for (int i = 0; i < pu.length; i++) {
            puNeg[i] = (ECPoint.AbstractF2m) pu[i].negate();
        }
        ECPoint.AbstractF2m q = (ECPoint.AbstractF2m) p.getCurve().getInfinity();
        int tauCount = 0;
        for (int i2 = u.length - 1; i2 >= 0; i2--) {
            tauCount++;
            byte b = u[i2];
            if (b != 0) {
                ECPoint.AbstractF2m q2 = q.tauPow(tauCount);
                tauCount = 0;
                q = (ECPoint.AbstractF2m) q2.add(b > 0 ? pu[b >>> 1] : puNeg[(-b) >>> 1]);
            }
        }
        if (tauCount > 0) {
            return q.tauPow(tauCount);
        }
        return q;
    }
}
