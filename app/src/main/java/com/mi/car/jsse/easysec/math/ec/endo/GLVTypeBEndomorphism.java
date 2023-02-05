package com.mi.car.jsse.easysec.math.ec.endo;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPointMap;
import com.mi.car.jsse.easysec.math.ec.ScaleXPointMap;
import java.math.BigInteger;

public class GLVTypeBEndomorphism implements GLVEndomorphism {
    protected final GLVTypeBParameters parameters;
    protected final ECPointMap pointMap;

    public GLVTypeBEndomorphism(ECCurve curve, GLVTypeBParameters parameters2) {
        this.parameters = parameters2;
        this.pointMap = new ScaleXPointMap(curve.fromBigInteger(parameters2.getBeta()));
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
