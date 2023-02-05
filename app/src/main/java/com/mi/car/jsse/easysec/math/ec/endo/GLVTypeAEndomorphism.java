package com.mi.car.jsse.easysec.math.ec.endo;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPointMap;
import com.mi.car.jsse.easysec.math.ec.ScaleYNegateXPointMap;
import java.math.BigInteger;

public class GLVTypeAEndomorphism implements GLVEndomorphism {
    protected final GLVTypeAParameters parameters;
    protected final ECPointMap pointMap;

    public GLVTypeAEndomorphism(ECCurve curve, GLVTypeAParameters parameters2) {
        this.parameters = parameters2;
        this.pointMap = new ScaleYNegateXPointMap(curve.fromBigInteger(parameters2.getI()));
    }

    @Override // com.mi.car.jsse.easysec.math.ec.endo.GLVEndomorphism
    public BigInteger[] decomposeScalar(BigInteger k) {
        return EndoUtil.decomposeScalar(this.parameters.getSplitParams(), k);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.endo.ECEndomorphism
    public ECPointMap getPointMap() {
        return this.pointMap;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.endo.ECEndomorphism
    public boolean hasEfficientPointMap() {
        return true;
    }
}
