//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.x9;

import com.mi.car.jsse.easysec.math.ec.ECCurve;

public abstract class X9ECParametersHolder {
    private ECCurve curve;
    private X9ECParameters params;

    public X9ECParametersHolder() {
    }

    public synchronized ECCurve getCurve() {
        if (this.curve == null) {
            this.curve = this.createCurve();
        }

        return this.curve;
    }

    public synchronized X9ECParameters getParameters() {
        if (this.params == null) {
            this.params = this.createParameters();
        }

        return this.params;
    }

    protected ECCurve createCurve() {
        return this.createParameters().getCurve();
    }

    protected abstract X9ECParameters createParameters();
}