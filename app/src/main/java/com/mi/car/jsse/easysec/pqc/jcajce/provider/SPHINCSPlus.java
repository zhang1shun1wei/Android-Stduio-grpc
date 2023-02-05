package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.asn1.bc.BCObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;

public class SPHINCSPlus {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincsplus.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.SPHINCSPLUS", "com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SPHINCSPLUS", "com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.SPHINCS+", "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.SPHINCS+", "SPHINCSPLUS");
            addSignatureAlgorithm(provider, "SPHINCSPLUS", "com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincsplus.SignatureSpi$Direct", BCObjectIdentifiers.sphincsPlus);
            provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus_shake_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus_sha_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus_sha_512.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus_shake_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus_sha_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus_sha_512.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature.SPHINCS+", "SPHINCSPLUS");
            AsymmetricKeyInfoConverter keyFact = new SPHINCSPlusKeyFactorySpi();
            registerOid(provider, BCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha_256, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha_512, "SPHINCSPLUS", keyFact);
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS");
        }
    }
}
