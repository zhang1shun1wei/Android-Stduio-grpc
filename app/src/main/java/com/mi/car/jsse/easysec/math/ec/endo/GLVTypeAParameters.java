package com.mi.car.jsse.easysec.math.ec.endo;

import java.math.BigInteger;

public class GLVTypeAParameters {
    protected final BigInteger i;
    protected final BigInteger lambda;
    protected final ScalarSplitParameters splitParams;

    public GLVTypeAParameters(BigInteger i2, BigInteger lambda2, ScalarSplitParameters splitParams2) {
        this.i = i2;
        this.lambda = lambda2;
        this.splitParams = splitParams2;
    }

    public BigInteger getI() {
        return this.i;
    }

    public BigInteger getLambda() {
        return this.lambda;
    }

    public ScalarSplitParameters getSplitParams() {
        return this.splitParams;
    }
}
