package com.mi.car.jsse.easysec.crypto.ec;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public interface ECPairTransform {
    void init(CipherParameters cipherParameters);

    ECPair transform(ECPair eCPair);
}
