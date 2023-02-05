package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.asn1.bc.BCObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.cmce.CMCEKeyFactorySpi;

public class CMCE {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.cmce.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.CMCE", "com.mi.car.jsse.easysec.pqc.jcajce.provider.cmce.CMCEKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.CMCE", "com.mi.car.jsse.easysec.pqc.jcajce.provider.cmce.CMCEKeyPairGeneratorSpi");
            provider.addAlgorithm("KeyGenerator.CMCE", "com.mi.car.jsse.easysec.pqc.jcajce.provider.cmce.CMCEKeyGeneratorSpi");
            AsymmetricKeyInfoConverter keyFact = new CMCEKeyFactorySpi();
            provider.addAlgorithm("Cipher.CMCE", "com.mi.car.jsse.easysec.pqc.jcajce.provider.cmce.CMCECipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_mceliece, "CMCE");
            registerOid(provider, BCObjectIdentifiers.pqc_kem_mceliece, "CMCE", keyFact);
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.pqc_kem_mceliece, "CMCE");
        }
    }
}
