package com.mi.car.jsse.easysec.crypto;

import java.math.BigInteger;

public interface DSAExt extends DSA {
    BigInteger getOrder();
}
