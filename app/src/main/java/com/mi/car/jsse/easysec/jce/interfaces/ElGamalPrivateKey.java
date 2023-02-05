package com.mi.car.jsse.easysec.jce.interfaces;

import java.math.BigInteger;
import javax.crypto.interfaces.DHPrivateKey;

public interface ElGamalPrivateKey extends ElGamalKey, DHPrivateKey {
    BigInteger getX();
}
