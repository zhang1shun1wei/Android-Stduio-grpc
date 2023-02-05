package com.mi.car.jsse.easysec.math.ec.endo;

import java.math.BigInteger;

public interface GLVEndomorphism extends ECEndomorphism {
    BigInteger[] decomposeScalar(BigInteger bigInteger);
}
