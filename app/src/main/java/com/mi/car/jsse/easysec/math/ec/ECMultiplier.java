package com.mi.car.jsse.easysec.math.ec;

import java.math.BigInteger;

public interface ECMultiplier {
    ECPoint multiply(ECPoint eCPoint, BigInteger bigInteger);
}
