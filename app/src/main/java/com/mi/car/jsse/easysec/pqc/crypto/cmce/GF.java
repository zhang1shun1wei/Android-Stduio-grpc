package com.mi.car.jsse.easysec.pqc.crypto.cmce;

abstract class GF {
    protected final int GFBITS;
    protected final int GFMASK;

    public GF(int gfbits) {
        this.GFBITS = gfbits;
        this.GFMASK = (1 << this.GFBITS) - 1;
    }

    short gf_iszero(short a) {
        int t = a - 1;
        t >>>= 19;
        return (short)t;
    }

    short gf_add(short left, short right) {
        return (short)(left ^ right);
    }

    protected abstract short gf_mul(short var1, short var2);

    protected abstract short gf_frac(short var1, short var2);

    protected abstract short gf_inv(short var1);
}
