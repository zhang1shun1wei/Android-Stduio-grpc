package com.mi.car.jsse.easysec.crypto.prng;

import com.mi.car.jsse.easysec.crypto.prng.drbg.SP80090DRBG;

/* access modifiers changed from: package-private */
public interface DRBGProvider {
    SP80090DRBG get(EntropySource entropySource);

    String getAlgorithm();
}
