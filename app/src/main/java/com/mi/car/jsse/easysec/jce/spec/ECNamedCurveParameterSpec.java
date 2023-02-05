package com.mi.car.jsse.easysec.jce.spec;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import java.math.BigInteger;

public class ECNamedCurveParameterSpec extends ECParameterSpec {
    private String name;

    public ECNamedCurveParameterSpec(String name2, ECCurve curve, ECPoint G, BigInteger n) {
        super(curve, G, n);
        this.name = name2;
    }

    public ECNamedCurveParameterSpec(String name2, ECCurve curve, ECPoint G, BigInteger n, BigInteger h) {
        super(curve, G, n, h);
        this.name = name2;
    }

    public ECNamedCurveParameterSpec(String name2, ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed) {
        super(curve, G, n, h, seed);
        this.name = name2;
    }

    public String getName() {
        return this.name;
    }
}
