package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla.QTESLAKeyFactorySpi;

public class QTESLA {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.QTESLA", "com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla.QTESLAKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.QTESLA", "com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla.KeyPairGeneratorSpi");
            provider.addAlgorithm("Signature.QTESLA", "com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla.SignatureSpi$qTESLA");
            addSignatureAlgorithm(provider, "QTESLA-P-I", "com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla.SignatureSpi$PI", PQCObjectIdentifiers.qTESLA_p_I);
            addSignatureAlgorithm(provider, "QTESLA-P-III", "com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla.SignatureSpi$PIII", PQCObjectIdentifiers.qTESLA_p_III);
            AsymmetricKeyInfoConverter keyFact = new QTESLAKeyFactorySpi();
            registerOid(provider, PQCObjectIdentifiers.qTESLA_p_I, "QTESLA-P-I", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_p_III, "QTESLA-P-III", keyFact);
        }
    }
}
