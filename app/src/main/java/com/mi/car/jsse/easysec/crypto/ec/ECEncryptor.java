package com.mi.car.jsse.easysec.crypto.ec;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.math.ec.ECPoint;

public interface ECEncryptor {
    ECPair encrypt(ECPoint eCPoint);

    void init(CipherParameters cipherParameters);
}
