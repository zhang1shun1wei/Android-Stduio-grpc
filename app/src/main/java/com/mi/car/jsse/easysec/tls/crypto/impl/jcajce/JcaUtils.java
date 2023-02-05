package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.HashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.util.Strings;
import java.security.Provider;
import java.security.Security;

/* access modifiers changed from: package-private */
public class JcaUtils {
    JcaUtils() {
    }

    static String getJcaAlgorithmName(SignatureAndHashAlgorithm algorithm) {
        return HashAlgorithm.getName(algorithm.getHash()) + "WITH" + Strings.toUpperCase(SignatureAlgorithm.getName(algorithm.getSignature()));
    }

    static boolean isSunMSCAPIProviderActive() {
        return Security.getProvider("SunMSCAPI") != null;
    }

    static boolean isSunMSCAPIProvider(Provider provider) {
        return provider != null && isSunMSCAPIProviderName(provider.getName());
    }

    static boolean isSunMSCAPIProviderName(String providerName) {
        return "SunMSCAPI".equals(providerName);
    }
}
