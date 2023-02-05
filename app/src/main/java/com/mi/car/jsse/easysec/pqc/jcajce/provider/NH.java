package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.newhope.NHKeyFactorySpi;

public class NH {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.newhope.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.NH", "com.mi.car.jsse.easysec.pqc.jcajce.provider.newhope.NHKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.NH", "com.mi.car.jsse.easysec.pqc.jcajce.provider.newhope.NHKeyPairGeneratorSpi");
            provider.addAlgorithm("KeyAgreement.NH", "com.mi.car.jsse.easysec.pqc.jcajce.provider.newhope.KeyAgreementSpi");
            registerOid(provider, PQCObjectIdentifiers.newHope, "NH", new NHKeyFactorySpi());
        }
    }
}
