package com.mi.car.jsse.easysec.math.ec;

public class ScaleYNegateXPointMap implements ECPointMap {
    protected final ECFieldElement scale;

    public ScaleYNegateXPointMap(ECFieldElement scale2) {
        this.scale = scale2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPointMap
    public ECPoint map(ECPoint p) {
        return p.scaleYNegateX(this.scale);
    }
}
