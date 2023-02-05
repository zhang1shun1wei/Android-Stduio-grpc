package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.asn1.bc.BCObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.saber.SABERKeyFactorySpi;

public class SABER {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.saber.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.SABER", "com.mi.car.jsse.easysec.pqc.jcajce.provider.saber.SABERKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SABER", "com.mi.car.jsse.easysec.pqc.jcajce.provider.saber.SABERKeyPairGeneratorSpi");
            provider.addAlgorithm("KeyGenerator.SABER", "com.mi.car.jsse.easysec.pqc.jcajce.provider.saber.SABERKeyGeneratorSpi");
            AsymmetricKeyInfoConverter keyFact = new SABERKeyFactorySpi();
            provider.addAlgorithm("Cipher.SABER", "com.mi.car.jsse.easysec.pqc.jcajce.provider.saber.SABERCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_saber, "SABER");
            registerOid(provider, BCObjectIdentifiers.pqc_kem_saber, "SABER", keyFact);
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.pqc_kem_saber, "SABER");
        }
    }
}
