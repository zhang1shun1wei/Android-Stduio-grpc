package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;

public class McEliece {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyPairGenerator.McElieceKobaraImai", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceCCA2KeyPairGeneratorSpi");
            provider.addAlgorithm("KeyPairGenerator.McEliecePointcheval", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceCCA2KeyPairGeneratorSpi");
            provider.addAlgorithm("KeyPairGenerator.McElieceFujisaki", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceCCA2KeyPairGeneratorSpi");
            provider.addAlgorithm("KeyPairGenerator.McEliece", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceKeyPairGeneratorSpi");
            provider.addAlgorithm("KeyPairGenerator.McEliece-CCA2", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceCCA2KeyPairGeneratorSpi");
            provider.addAlgorithm("KeyFactory.McElieceKobaraImai", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceCCA2KeyFactorySpi");
            provider.addAlgorithm("KeyFactory.McEliecePointcheval", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceCCA2KeyFactorySpi");
            provider.addAlgorithm("KeyFactory.McElieceFujisaki", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceCCA2KeyFactorySpi");
            provider.addAlgorithm("KeyFactory.McEliece", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceKeyFactorySpi");
            provider.addAlgorithm("KeyFactory.McEliece-CCA2", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceCCA2KeyFactorySpi");
            provider.addAlgorithm("KeyFactory." + PQCObjectIdentifiers.mcElieceCca2, "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceCCA2KeyFactorySpi");
            provider.addAlgorithm("KeyFactory." + PQCObjectIdentifiers.mcEliece, "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceKeyFactorySpi");
            provider.addAlgorithm("Cipher.McEliece", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McEliecePKCSCipherSpi$McEliecePKCS");
            provider.addAlgorithm("Cipher.McEliecePointcheval", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McEliecePointchevalCipherSpi$McEliecePointcheval");
            provider.addAlgorithm("Cipher.McElieceKobaraImai", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi$McElieceKobaraImai");
            provider.addAlgorithm("Cipher.McElieceFujisaki", "com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceFujisakiCipherSpi$McElieceFujisaki");
        }
    }
}
