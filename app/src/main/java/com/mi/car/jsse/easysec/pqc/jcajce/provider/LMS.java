package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class LMS {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.lms.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.LMS", "com.mi.car.jsse.easysec.pqc.jcajce.provider.lms.LMSKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory." + PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS");
            provider.addAlgorithm("KeyPairGenerator.LMS", "com.mi.car.jsse.easysec.pqc.jcajce.provider.lms.LMSKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator." + PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS");
            provider.addAlgorithm("Signature.LMS", "com.mi.car.jsse.easysec.pqc.jcajce.provider.lms.LMSSignatureSpi$generic");
            provider.addAlgorithm("Alg.Alias.Signature." + PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS");
        }
    }
}
