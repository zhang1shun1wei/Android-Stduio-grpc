package com.mi.car.jsse.easysec.math.ec.endo;

import java.math.BigInteger;

public class GLVTypeBParameters {
    protected final BigInteger beta;
    protected final BigInteger lambda;
    protected final ScalarSplitParameters splitParams;

    public GLVTypeBParameters(BigInteger beta2, BigInteger lambda2, ScalarSplitParameters splitParams2) {
        this.beta = beta2;
        this.lambda = lambda2;
        this.splitParams = splitParams2;
    }

    public BigInteger getBeta() {
        return this.beta;
    }

    public BigInteger getLambda() {
        return this.lambda;
    }

    public ScalarSplitParameters getSplitParams() {
        return this.splitParams;
    }
}
