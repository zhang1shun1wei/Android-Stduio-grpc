package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/* access modifiers changed from: package-private */
public class RSAUtil {
    RSAUtil() {
    }

    static String getDigestSigAlgName(String name) {
        int dIndex = name.indexOf(45);
        if (dIndex <= 0 || name.startsWith("SHA3")) {
            return name;
        }
        return name.substring(0, dIndex) + name.substring(dIndex + 1);
    }

    static AlgorithmParameterSpec getPSSParameterSpec(int cryptoHashAlgorithm, String digestName, JcaJceHelper helper) {
        return new PSSParameterSpec(digestName, "MGF1", new MGF1ParameterSpec(digestName), TlsCryptoUtils.getHashOutputSize(cryptoHashAlgorithm), 1);
    }
}
