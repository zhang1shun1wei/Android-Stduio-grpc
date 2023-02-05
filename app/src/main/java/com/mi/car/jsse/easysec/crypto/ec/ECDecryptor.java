package com.mi.car.jsse.easysec.crypto.ec;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.math.ec.ECPoint;

public interface ECDecryptor {
    ECPoint decrypt(ECPair eCPair);

    void init(CipherParameters cipherParameters);
}
