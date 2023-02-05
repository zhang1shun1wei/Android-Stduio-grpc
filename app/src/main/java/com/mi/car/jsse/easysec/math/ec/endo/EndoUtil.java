package com.mi.car.jsse.easysec.math.ec.endo;

import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.ec.PreCompCallback;
import com.mi.car.jsse.easysec.math.ec.PreCompInfo;
import java.math.BigInteger;

public abstract class EndoUtil {
    public static final String PRECOMP_NAME = "bc_endo";

    public static BigInteger[] decomposeScalar(ScalarSplitParameters p, BigInteger k) {
        int bits = p.getBits();
        BigInteger b1 = calculateB(k, p.getG1(), bits);
        BigInteger b2 = calculateB(k, p.getG2(), bits);
        return new BigInteger[]{k.subtract(b1.multiply(p.getV1A()).add(b2.multiply(p.getV2A()))), b1.multiply(p.getV1B()).add(b2.multiply(p.getV2B())).negate()};
    }

    public static ECPoint mapPoint(final ECEndomorphism endomorphism, final ECPoint p) {
        return ((EndoPreCompInfo) p.getCurve().precompute(p, PRECOMP_NAME, new PreCompCallback() {
            /* class com.mi.car.jsse.easysec.math.ec.endo.EndoUtil.AnonymousClass1 */

            @Override // com.mi.car.jsse.easysec.math.ec.PreCompCallback
            public PreCompInfo precompute(PreCompInfo existing) {
                EndoPreCompInfo existingEndo = existing instanceof EndoPreCompInfo ? (EndoPreCompInfo) existing : null;
                if (checkExisting(existingEndo, endomorphism)) {
                    return existingEndo;
                }
                ECPoint mappedPoint = endomorphism.getPointMap().map(p);
                EndoPreCompInfo result = new EndoPreCompInfo();
                result.setEndomorphism(endomorphism);
                result.setMappedPoint(mappedPoint);
                return result;
            }

            private boolean checkExisting(EndoPreCompInfo existingEndo, ECEndomorphism endomorphism) {
                return (existingEndo == null || existingEndo.getEndomorphism() != endomorphism || existingEndo.getMappedPoint() == null) ? false : true;
            }
        })).getMappedPoint();
    }

    private static BigInteger calculateB(BigInteger k, BigInteger g, int t) {
        boolean negative = g.signum() < 0;
        BigInteger b = k.multiply(g.abs());
        boolean extra = b.testBit(t - 1);
        BigInteger b2 = b.shiftRight(t);
        if (extra) {
            b2 = b2.add(ECConstants.ONE);
        }
        return negative ? b2.negate() : b2;
    }
}
