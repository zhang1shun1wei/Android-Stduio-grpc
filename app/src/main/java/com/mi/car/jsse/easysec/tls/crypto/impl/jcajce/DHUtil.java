package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.jcajce.spec.DHDomainParameterSpec;
import com.mi.car.jsse.easysec.jcajce.spec.DHExtendedPublicKeySpec;
import com.mi.car.jsse.easysec.tls.crypto.DHGroup;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.spec.DHParameterSpec;

/* access modifiers changed from: package-private */
public class DHUtil {
    DHUtil() {
    }

    static AlgorithmParameterSpec createInitSpec(DHGroup dhGroup) {
        return new DHDomainParameterSpec(dhGroup.getP(), dhGroup.getQ(), dhGroup.getG(), dhGroup.getL());
    }

    static KeySpec createPublicKeySpec(BigInteger y, DHParameterSpec dhSpec) {
        return new DHExtendedPublicKeySpec(y, dhSpec);
    }

    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto crypto, DHGroup dhGroup) {
        return getAlgorithmParameters(crypto, createInitSpec(dhGroup));
    }

    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto crypto, AlgorithmParameterSpec initSpec) {
        try {
            AlgorithmParameters dhAlgParams = crypto.getHelper().createAlgorithmParameters("DiffieHellman");
            dhAlgParams.init(initSpec);
            if (((DHParameterSpec) dhAlgParams.getParameterSpec(DHParameterSpec.class)) != null) {
                return dhAlgParams;
            }
            return null;
        } catch (AssertionError | Exception e) {
        }
        return null;
    }

    static DHParameterSpec getDHParameterSpec(JcaTlsCrypto crypto, DHGroup dhGroup) {
        return getDHParameterSpec(crypto, createInitSpec(dhGroup));
    }

    static DHParameterSpec getDHParameterSpec(JcaTlsCrypto crypto, AlgorithmParameterSpec initSpec) {
        try {
            AlgorithmParameters dhAlgParams = crypto.getHelper().createAlgorithmParameters("DiffieHellman");
            dhAlgParams.init(initSpec);
            DHParameterSpec dhSpec = (DHParameterSpec) dhAlgParams.getParameterSpec(DHParameterSpec.class);
            if (dhSpec != null) {
                return dhSpec;
            }
            return null;
        } catch (AssertionError | Exception e) {
        }
        return null;
    }

    static BigInteger getQ(DHParameterSpec dhSpec) {
        if (dhSpec instanceof DHDomainParameterSpec) {
            return ((DHDomainParameterSpec) dhSpec).getQ();
        }
        return null;
    }

    static boolean isGroupSupported(JcaTlsCrypto crypto, DHGroup dhGroup) {
        return (dhGroup == null || getDHParameterSpec(crypto, dhGroup) == null) ? false : true;
    }
}
