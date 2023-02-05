package com.mi.car.jsse.easysec.math.ec;

public class ScaleYPointMap implements ECPointMap {
    protected final ECFieldElement scale;

    public ScaleYPointMap(ECFieldElement scale2) {
        this.scale = scale2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPointMap
    public ECPoint map(ECPoint p) {
        return p.scaleY(this.scale);
    }
}
