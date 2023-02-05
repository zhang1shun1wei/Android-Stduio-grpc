package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.asn1.bc.BCObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.frodo.FrodoKeyFactorySpi;

public class Frodo {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.frodo.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.FRODO", "com.mi.car.jsse.easysec.pqc.jcajce.provider.frodo.FrodoKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.FRODO", "com.mi.car.jsse.easysec.pqc.jcajce.provider.frodo.FrodoKeyPairGeneratorSpi");
            provider.addAlgorithm("KeyGenerator.FRODO", "com.mi.car.jsse.easysec.pqc.jcajce.provider.frodo.FrodoKeyGeneratorSpi");
            AsymmetricKeyInfoConverter keyFact = new FrodoKeyFactorySpi();
            provider.addAlgorithm("Cipher.FRODO", "com.mi.car.jsse.easysec.pqc.jcajce.provider.frodo.FrodoCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_frodo, "FRODO");
            registerOid(provider, BCObjectIdentifiers.pqc_kem_frodo, "Frodo", keyFact);
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.pqc_kem_frodo, "FRODO");
        }
    }
}
