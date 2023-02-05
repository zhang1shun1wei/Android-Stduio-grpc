package com.mi.car.jsse.easysec.jce;

import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.EC5Util;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class ECPointUtil {
    public static ECPoint decodePoint(EllipticCurve curve, byte[] encoded) {
        ECCurve c;
        if (curve.getField() instanceof ECFieldFp) {
            c = new ECCurve.Fp(((ECFieldFp) curve.getField()).getP(), curve.getA(), curve.getB());
        } else {
            int[] k = ((ECFieldF2m) curve.getField()).getMidTermsOfReductionPolynomial();
            if (k.length == 3) {
                c = new ECCurve.F2m(((ECFieldF2m) curve.getField()).getM(), k[2], k[1], k[0], curve.getA(), curve.getB());
            } else {
                c = new ECCurve.F2m(((ECFieldF2m) curve.getField()).getM(), k[0], curve.getA(), curve.getB());
            }
        }
        return EC5Util.convertPoint(c.decodePoint(encoded));
    }
}
