package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs.Sphincs256KeyFactorySpi;

public class SPHINCS {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.SPHINCS256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs.Sphincs256KeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SPHINCS256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs.Sphincs256KeyPairGeneratorSpi");
            addSignatureAlgorithm(provider, "SHA512", "SPHINCS256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs.SignatureSpi$withSha512", PQCObjectIdentifiers.sphincs256_with_SHA512);
            addSignatureAlgorithm(provider, "SHA3-512", "SPHINCS256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs.SignatureSpi$withSha3_512", PQCObjectIdentifiers.sphincs256_with_SHA3_512);
            registerOid(provider, PQCObjectIdentifiers.sphincs256, "SPHINCS256", new Sphincs256KeyFactorySpi());
            registerOidAlgorithmParameters(provider, PQCObjectIdentifiers.sphincs256, "SPHINCS256");
        }
    }
}
