package com.mi.car.jsse.easysec.math.ec;

import com.mi.car.jsse.easysec.math.ec.ECPoint;

public class WTauNafPreCompInfo implements PreCompInfo {
    protected ECPoint.AbstractF2m[] preComp = null;

    public ECPoint.AbstractF2m[] getPreComp() {
        return this.preComp;
    }

    public void setPreComp(ECPoint.AbstractF2m[] preComp2) {
        this.preComp = preComp2;
    }
}
