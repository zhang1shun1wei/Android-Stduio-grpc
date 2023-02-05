package com.mi.car.jsse.easysec.pqc.jcajce.provider.util;

import com.mi.car.jsse.easysec.crypto.Wrapper;
import com.mi.car.jsse.easysec.crypto.engines.AESEngine;
import com.mi.car.jsse.easysec.crypto.engines.ARIAEngine;
import com.mi.car.jsse.easysec.crypto.engines.CamelliaEngine;
import com.mi.car.jsse.easysec.crypto.engines.RFC3394WrapEngine;
import com.mi.car.jsse.easysec.crypto.engines.RFC5649WrapEngine;
import com.mi.car.jsse.easysec.crypto.engines.SEEDEngine;

public class WrapUtil {
    public static Wrapper getWrapper(String keyAlgorithmName) {
        if (keyAlgorithmName.equalsIgnoreCase("AES")) {
            return new RFC3394WrapEngine(new AESEngine());
        }
        if (keyAlgorithmName.equalsIgnoreCase("ARIA")) {
            return new RFC3394WrapEngine(new ARIAEngine());
        }
        if (keyAlgorithmName.equalsIgnoreCase("Camellia")) {
            return new RFC3394WrapEngine(new CamelliaEngine());
        }
        if (keyAlgorithmName.equalsIgnoreCase("SEED")) {
            return new RFC3394WrapEngine(new SEEDEngine());
        }
        if (keyAlgorithmName.equalsIgnoreCase("AES-KWP")) {
            return new RFC5649WrapEngine(new AESEngine());
        }
        if (keyAlgorithmName.equalsIgnoreCase("Camellia-KWP")) {
            return new RFC5649WrapEngine(new CamelliaEngine());
        }
        if (keyAlgorithmName.equalsIgnoreCase("ARIA-KWP")) {
            return new RFC5649WrapEngine(new ARIAEngine());
        }
        throw new UnsupportedOperationException("unknown key algorithm: " + keyAlgorithmName);
    }
}
