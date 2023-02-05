package com.mi.car.jsse.easysec.math.ec.endo;

import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.ec.PreCompInfo;

public class EndoPreCompInfo implements PreCompInfo {
    protected ECEndomorphism endomorphism;
    protected ECPoint mappedPoint;

    public ECEndomorphism getEndomorphism() {
        return this.endomorphism;
    }

    public void setEndomorphism(ECEndomorphism endomorphism2) {
        this.endomorphism = endomorphism2;
    }

    public ECPoint getMappedPoint() {
        return this.mappedPoint;
    }

    public void setMappedPoint(ECPoint mappedPoint2) {
        this.mappedPoint = mappedPoint2;
    }
}
