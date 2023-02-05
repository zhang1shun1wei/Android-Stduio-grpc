package com.mi.car.jsse.easysec.pqc.math.ntru.polynomial;

import com.mi.car.jsse.easysec.pqc.math.ntru.euclid.BigIntEuclidean;
import java.math.BigInteger;

public class ModularResultant extends Resultant {
    BigInteger modulus;

    ModularResultant(BigIntPolynomial rho, BigInteger res, BigInteger modulus2) {
        super(rho, res);
        this.modulus = modulus2;
    }

    static ModularResultant combineRho(ModularResultant modRes1, ModularResultant modRes2) {
        BigInteger mod1 = modRes1.modulus;
        BigInteger mod2 = modRes2.modulus;
        BigInteger prod = mod1.multiply(mod2);
        BigIntEuclidean er = BigIntEuclidean.calculate(mod2, mod1);
        BigIntPolynomial rho1 = (BigIntPolynomial) modRes1.rho.clone();
        rho1.mult(er.x.multiply(mod2));
        BigIntPolynomial rho2 = (BigIntPolynomial) modRes2.rho.clone();
        rho2.mult(er.y.multiply(mod1));
        rho1.add(rho2);
        rho1.mod(prod);
        return new ModularResultant(rho1, null, prod);
    }
}
