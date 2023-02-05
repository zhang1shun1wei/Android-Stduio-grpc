package com.mi.car.jsse.easysec.math.ec;

public class ScaleXNegateYPointMap implements ECPointMap {
    protected final ECFieldElement scale;

    public ScaleXNegateYPointMap(ECFieldElement scale2) {
        this.scale = scale2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPointMap
    public ECPoint map(ECPoint p) {
        return p.scaleXNegateY(this.scale);
    }
}
