package com.mi.car.jsse.easysec.jce.interfaces;

import com.mi.car.jsse.easysec.math.ec.ECPoint;
import java.security.PublicKey;

public interface ECPublicKey extends ECKey, PublicKey {
    ECPoint getQ();
}
