package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.asn1.bc.BCObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.isara.IsaraObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSKeyFactorySpi;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTKeyFactorySpi;

public class XMSS {
    private static final String PREFIX = "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.";

    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.XMSS", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.XMSS", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSKeyPairGeneratorSpi");
            provider.addAlgorithm("Signature.XMSS", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSSignatureSpi$generic");
            provider.addAlgorithm("Alg.Alias.Signature." + IsaraObjectIdentifiers.id_alg_xmss, "XMSS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + IsaraObjectIdentifiers.id_alg_xmss, "XMSS");
            addSignatureAlgorithm(provider, "XMSS-SHA256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSSignatureSpi$withSha256", BCObjectIdentifiers.xmss_SHA256);
            addSignatureAlgorithm(provider, "XMSS-SHAKE128", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSSignatureSpi$withShake128", BCObjectIdentifiers.xmss_SHAKE128);
            addSignatureAlgorithm(provider, "XMSS-SHA512", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSSignatureSpi$withSha512", BCObjectIdentifiers.xmss_SHA512);
            addSignatureAlgorithm(provider, "XMSS-SHAKE256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSSignatureSpi$withShake256", BCObjectIdentifiers.xmss_SHAKE256);
            addSignatureAlgorithm(provider, "SHA256", "XMSS-SHA256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSSignatureSpi$withSha256andPrehash", BCObjectIdentifiers.xmss_SHA256ph);
            addSignatureAlgorithm(provider, "SHAKE128", "XMSS-SHAKE128", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSSignatureSpi$withShake128andPrehash", BCObjectIdentifiers.xmss_SHAKE128ph);
            addSignatureAlgorithm(provider, "SHA512", "XMSS-SHA512", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSSignatureSpi$withSha512andPrehash", BCObjectIdentifiers.xmss_SHA512ph);
            addSignatureAlgorithm(provider, "SHAKE256", "XMSS-SHAKE256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSSignatureSpi$withShake256andPrehash", BCObjectIdentifiers.xmss_SHAKE256ph);
            provider.addAlgorithm("Alg.Alias.Signature.SHA256WITHXMSS", "SHA256WITHXMSS-SHA256");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE128WITHXMSS", "SHAKE128WITHXMSS-SHAKE128");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHXMSS", "SHA512WITHXMSS-SHA512");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE256WITHXMSS", "SHAKE256WITHXMSS-SHAKE256");
            provider.addAlgorithm("KeyFactory.XMSSMT", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.XMSSMT", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTKeyPairGeneratorSpi");
            provider.addAlgorithm("Signature.XMSSMT", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTSignatureSpi$generic");
            provider.addAlgorithm("Alg.Alias.Signature." + IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");
            addSignatureAlgorithm(provider, "XMSSMT-SHA256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTSignatureSpi$withSha256", BCObjectIdentifiers.xmss_mt_SHA256);
            addSignatureAlgorithm(provider, "XMSSMT-SHAKE128", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTSignatureSpi$withShake128", BCObjectIdentifiers.xmss_mt_SHAKE128);
            addSignatureAlgorithm(provider, "XMSSMT-SHA512", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTSignatureSpi$withSha512", BCObjectIdentifiers.xmss_mt_SHA512);
            addSignatureAlgorithm(provider, "XMSSMT-SHAKE256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTSignatureSpi$withShake256", BCObjectIdentifiers.xmss_mt_SHAKE256);
            addSignatureAlgorithm(provider, "SHA256", "XMSSMT-SHA256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTSignatureSpi$withSha256andPrehash", BCObjectIdentifiers.xmss_mt_SHA256ph);
            addSignatureAlgorithm(provider, "SHAKE128", "XMSSMT-SHAKE128", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTSignatureSpi$withShake128andPrehash", BCObjectIdentifiers.xmss_mt_SHAKE128ph);
            addSignatureAlgorithm(provider, "SHA512", "XMSSMT-SHA512", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTSignatureSpi$withSha512andPrehash", BCObjectIdentifiers.xmss_mt_SHA512ph);
            addSignatureAlgorithm(provider, "SHAKE256", "XMSSMT-SHAKE256", "com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTSignatureSpi$withShake256andPrehash", BCObjectIdentifiers.xmss_mt_SHAKE256ph);
            provider.addAlgorithm("Alg.Alias.Signature.SHA256WITHXMSSMT", "SHA256WITHXMSSMT-SHA256");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE128WITHXMSSMT", "SHAKE128WITHXMSSMT-SHAKE128");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHXMSSMT", "SHA512WITHXMSSMT-SHA512");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE256WITHXMSSMT", "SHAKE256WITHXMSSMT-SHAKE256");
            registerOid(provider, PQCObjectIdentifiers.xmss, "XMSS", new XMSSKeyFactorySpi());
            registerOid(provider, IsaraObjectIdentifiers.id_alg_xmss, "XMSS", new XMSSKeyFactorySpi());
            registerOid(provider, PQCObjectIdentifiers.xmss_mt, "XMSSMT", new XMSSMTKeyFactorySpi());
            registerOid(provider, IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT", new XMSSMTKeyFactorySpi());
        }
    }
}
