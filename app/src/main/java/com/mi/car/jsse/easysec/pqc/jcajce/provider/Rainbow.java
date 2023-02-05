package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow.RainbowKeyFactorySpi;

public class Rainbow {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.Rainbow", "com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow.RainbowKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.Rainbow", "com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow.RainbowKeyPairGeneratorSpi");
            addSignatureAlgorithm(provider, "SHA224", "Rainbow", "com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow.SignatureSpi$withSha224", PQCObjectIdentifiers.rainbowWithSha224);
            addSignatureAlgorithm(provider, "SHA256", "Rainbow", "com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow.SignatureSpi$withSha256", PQCObjectIdentifiers.rainbowWithSha256);
            addSignatureAlgorithm(provider, "SHA384", "Rainbow", "com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow.SignatureSpi$withSha384", PQCObjectIdentifiers.rainbowWithSha384);
            addSignatureAlgorithm(provider, "SHA512", "Rainbow", "com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow.SignatureSpi$withSha512", PQCObjectIdentifiers.rainbowWithSha512);
            registerOid(provider, PQCObjectIdentifiers.rainbow, "Rainbow", new RainbowKeyFactorySpi());
        }
    }
}
