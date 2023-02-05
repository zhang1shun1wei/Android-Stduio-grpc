package com.mi.car.jsse.easysec.pqc.math.ntru.polynomial;

import java.math.BigInteger;

public class Resultant {
    public BigInteger res;
    public BigIntPolynomial rho;

    Resultant(BigIntPolynomial rho2, BigInteger res2) {
        this.rho = rho2;
        this.res = res2;
    }
}
