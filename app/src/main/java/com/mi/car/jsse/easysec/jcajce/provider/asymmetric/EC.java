//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.jcajce.provider.asymmetric;

import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.sec.SECObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.internal.asn1.bsi.BSIObjectIdentifiers;
import com.mi.car.jsse.easysec.internal.asn1.cms.CMSObjectIdentifiers;
import com.mi.car.jsse.easysec.internal.asn1.eac.EACObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.ECMQV;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.util.Properties;
import java.util.HashMap;
import java.util.Map;

public class EC {
    private static final String PREFIX = "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.";
    private static final Map<String, String> generalEcAttributes = new HashMap();

    public EC() {
    }

    static {
        generalEcAttributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        generalEcAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings extends AsymmetricAlgorithmProvider {
        public Mappings() {
        }

        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("AlgorithmParameters.EC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.AlgorithmParametersSpi");
            provider.addAttributes("KeyAgreement.ECDH", EC.generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECDH", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DH");
            provider.addAttributes("KeyAgreement.ECDHC", EC.generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECDHC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHC");
            provider.addAttributes("KeyAgreement.ECCDH", EC.generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECCDH", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHC");
            provider.addAttributes("KeyAgreement.ECCDHU", EC.generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECCDHU", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUC");
            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA1KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA1KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA1KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$CDHwithSHA1KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA224KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA224KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA224KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$CDHwithSHA224KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA256KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA256KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA256KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$CDHwithSHA256KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA384KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA384KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA384KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$CDHwithSHA384KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA512KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA512KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA512KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$CDHwithSHA512KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA1KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$CDHwithSHA1KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA224KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$CDHwithSHA224KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA256KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$CDHwithSHA256KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA384KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$CDHwithSHA384KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA512KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$CDHwithSHA512KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA1CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA1CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA256CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA256CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA384CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA384CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA512CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA512CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA1CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUwithSHA1CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA224CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUwithSHA224CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA256CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUwithSHA256CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA384CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUwithSHA384CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA512CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUwithSHA512CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA1KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA224KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA256KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA384KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA512KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHUwithSHA512KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA1KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA224KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA256KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA384KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA512KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithSHA512KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA1, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA224, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA256, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA384, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA512, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithSHA512KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_RIPEMD160, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithRIPEMD160KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHRIPEMD160KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$ECKAEGwithRIPEMD160KDF");
            this.registerOid(provider, X9ObjectIdentifiers.id_ecPublicKey, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
            this.registerOid(provider, X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
            this.registerOid(provider, X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "ECMQV", new ECMQV());
            this.registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
            this.registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
            this.registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
            this.registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
            this.registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
            this.registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
            this.registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
            this.registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
            this.registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.id_ecPublicKey, "EC");
            this.registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "EC");
            this.registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme, "EC");
            this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme, "EC");
            this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme, "EC");
            this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme, "EC");
            this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme, "EC");
            this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme, "EC");
            this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme, "EC");
            this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme, "EC");
            this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme, "EC");
            if (!Properties.isOverrideSet("com.mi.car.jsse.easysec.ec.disable_mqv")) {
                provider.addAlgorithm("KeyAgreement.ECMQV", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQV");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA1CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA1CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA224CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA224CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA256CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA256CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA384CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA384CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA512CKDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA512CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA1KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA1KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA224KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA224KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA256KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA256KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA384KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA384KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA512KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA512KDF");
                provider.addAlgorithm("KeyAgreement." + X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA1KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA224KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA256KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA384KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA512KDFAndSharedInfo");
                this.registerOid(provider, X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "EC", new com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
                this.registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "EC");
                this.registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme, "ECMQV", new ECMQV());
                this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme, "EC");
                this.registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme, "ECMQV", new ECMQV());
                this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme, "EC");
                this.registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme, "ECMQV", new ECMQV());
                this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme, "EC");
                this.registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, "ECMQV", new ECMQV());
                this.registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, "EC");
                provider.addAlgorithm("KeyFactory.ECMQV", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi$ECMQV");
                provider.addAlgorithm("KeyPairGenerator.ECMQV", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECMQV");
            }

            provider.addAlgorithm("KeyFactory.EC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi$EC");
            provider.addAlgorithm("KeyFactory.ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi$ECDSA");
            provider.addAlgorithm("KeyFactory.ECDH", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi$ECDH");
            provider.addAlgorithm("KeyFactory.ECDHC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyFactorySpi$ECDHC");
            provider.addAlgorithm("KeyPairGenerator.EC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$EC");
            provider.addAlgorithm("KeyPairGenerator.ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDSA");
            provider.addAlgorithm("KeyPairGenerator.ECDH", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDH");
            provider.addAlgorithm("KeyPairGenerator.ECDHWITHSHA1KDF", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDH");
            provider.addAlgorithm("KeyPairGenerator.ECDHC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDHC");
            provider.addAlgorithm("KeyPairGenerator.ECIES", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDH");
            provider.addAlgorithm("Cipher.ECIES", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIES");
            provider.addAlgorithm("Cipher.ECIESwithSHA1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIES");
            provider.addAlgorithm("Cipher.ECIESWITHSHA1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIES");
            provider.addAlgorithm("Cipher.ECIESwithSHA256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA256");
            provider.addAlgorithm("Cipher.ECIESWITHSHA256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA256");
            provider.addAlgorithm("Cipher.ECIESwithSHA384", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA384");
            provider.addAlgorithm("Cipher.ECIESWITHSHA384", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA384");
            provider.addAlgorithm("Cipher.ECIESwithSHA512", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA512");
            provider.addAlgorithm("Cipher.ECIESWITHSHA512", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA512");
            provider.addAlgorithm("Cipher.ECIESwithAES-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithAESCBC");
            provider.addAlgorithm("Cipher.ECIESWITHAES-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithAESCBC");
            provider.addAlgorithm("Cipher.ECIESwithSHA1andAES-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithAESCBC");
            provider.addAlgorithm("Cipher.ECIESWITHSHA1ANDAES-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithAESCBC");
            provider.addAlgorithm("Cipher.ECIESwithSHA256andAES-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA256andAESCBC");
            provider.addAlgorithm("Cipher.ECIESWITHSHA256ANDAES-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA256andAESCBC");
            provider.addAlgorithm("Cipher.ECIESwithSHA384andAES-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA384andAESCBC");
            provider.addAlgorithm("Cipher.ECIESWITHSHA384ANDAES-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA384andAESCBC");
            provider.addAlgorithm("Cipher.ECIESwithSHA512andAES-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA512andAESCBC");
            provider.addAlgorithm("Cipher.ECIESWITHSHA512ANDAES-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA512andAESCBC");
            provider.addAlgorithm("Cipher.ECIESwithDESEDE-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESWITHDESEDE-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESwithSHA1andDESEDE-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESWITHSHA1ANDDESEDE-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESwithSHA256andDESEDE-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA256andDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESWITHSHA256ANDDESEDE-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA256andDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESwithSHA384andDESEDE-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA384andDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESWITHSHA384ANDDESEDE-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA384andDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESwithSHA512andDESEDE-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA512andDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESWITHSHA512ANDDESEDE-CBC", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithSHA512andDESedeCBC");
            provider.addAlgorithm("Cipher.ETSIKEMWITHSHA256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.IESKEMCipher$KEMwithSHA256");
            provider.addAlgorithm("Signature.ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSA");
            provider.addAlgorithm("Signature.NONEwithECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSAnone");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1withECDSA", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.ECDSAwithSHA1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WITHECDSA", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.ECDSAWITHSHA1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WithECDSA", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.ECDSAWithSHA1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.1.2.840.10045.4.1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature." + TeleTrusTObjectIdentifiers.ecSignWithSha1, "ECDSA");
            provider.addAlgorithm("Signature.ECDDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDetDSA");
            provider.addAlgorithm("Signature.SHA1WITHECDDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDetDSA");
            provider.addAlgorithm("Signature.SHA224WITHECDDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDetDSA224");
            provider.addAlgorithm("Signature.SHA256WITHECDDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDetDSA256");
            provider.addAlgorithm("Signature.SHA384WITHECDDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDetDSA384");
            provider.addAlgorithm("Signature.SHA512WITHECDDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDetDSA512");
            provider.addAlgorithm("Signature.SHA3-224WITHECDDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDetDSASha3_224");
            provider.addAlgorithm("Signature.SHA3-256WITHECDDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDetDSASha3_256");
            provider.addAlgorithm("Signature.SHA3-384WITHECDDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDetDSASha3_384");
            provider.addAlgorithm("Signature.SHA3-512WITHECDDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDetDSASha3_512");
            provider.addAlgorithm("Alg.Alias.Signature.DETECDSA", "ECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WITHDETECDSA", "SHA1WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA224WITHDETECDSA", "SHA224WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA256WITHDETECDSA", "SHA256WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA384WITHDETECDSA", "SHA384WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHDETECDSA", "SHA512WITHECDDSA");
            this.addSignatureAlgorithm(provider, "SHA224", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSA224", X9ObjectIdentifiers.ecdsa_with_SHA224);
            this.addSignatureAlgorithm(provider, "SHA256", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSA256", X9ObjectIdentifiers.ecdsa_with_SHA256);
            this.addSignatureAlgorithm(provider, "SHA384", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSA384", X9ObjectIdentifiers.ecdsa_with_SHA384);
            this.addSignatureAlgorithm(provider, "SHA512", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSA512", X9ObjectIdentifiers.ecdsa_with_SHA512);
            this.addSignatureAlgorithm(provider, "SHA3-224", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSASha3_224", NISTObjectIdentifiers.id_ecdsa_with_sha3_224);
            this.addSignatureAlgorithm(provider, "SHA3-256", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSASha3_256", NISTObjectIdentifiers.id_ecdsa_with_sha3_256);
            this.addSignatureAlgorithm(provider, "SHA3-384", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSASha3_384", NISTObjectIdentifiers.id_ecdsa_with_sha3_384);
            this.addSignatureAlgorithm(provider, "SHA3-512", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSASha3_512", NISTObjectIdentifiers.id_ecdsa_with_sha3_512);
            this.addSignatureAlgorithm(provider, "SHAKE128", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSAShake128", CMSObjectIdentifiers.id_ecdsa_with_shake128);
            this.addSignatureAlgorithm(provider, "SHAKE256", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSAShake256", CMSObjectIdentifiers.id_ecdsa_with_shake256);
            this.addSignatureAlgorithm(provider, "RIPEMD160", "ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSARipeMD160", TeleTrusTObjectIdentifiers.ecSignWithRipemd160);
            provider.addAlgorithm("Signature.SHA1WITHECNR", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecNR");
            provider.addAlgorithm("Signature.SHA224WITHECNR", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecNR224");
            provider.addAlgorithm("Signature.SHA256WITHECNR", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecNR256");
            provider.addAlgorithm("Signature.SHA384WITHECNR", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecNR384");
            provider.addAlgorithm("Signature.SHA512WITHECNR", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecNR512");
            this.addSignatureAlgorithm(provider, "SHA1", "CVC-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1);
            this.addSignatureAlgorithm(provider, "SHA224", "CVC-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA224", EACObjectIdentifiers.id_TA_ECDSA_SHA_224);
            this.addSignatureAlgorithm(provider, "SHA256", "CVC-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA256", EACObjectIdentifiers.id_TA_ECDSA_SHA_256);
            this.addSignatureAlgorithm(provider, "SHA384", "CVC-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA384", EACObjectIdentifiers.id_TA_ECDSA_SHA_384);
            this.addSignatureAlgorithm(provider, "SHA512", "CVC-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA512", EACObjectIdentifiers.id_TA_ECDSA_SHA_512);
            this.addSignatureAlgorithm(provider, "SHA1", "PLAIN-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA", BSIObjectIdentifiers.ecdsa_plain_SHA1);
            this.addSignatureAlgorithm(provider, "SHA224", "PLAIN-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA224", BSIObjectIdentifiers.ecdsa_plain_SHA224);
            this.addSignatureAlgorithm(provider, "SHA256", "PLAIN-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA256", BSIObjectIdentifiers.ecdsa_plain_SHA256);
            this.addSignatureAlgorithm(provider, "SHA384", "PLAIN-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA384", BSIObjectIdentifiers.ecdsa_plain_SHA384);
            this.addSignatureAlgorithm(provider, "SHA512", "PLAIN-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA512", BSIObjectIdentifiers.ecdsa_plain_SHA512);
            this.addSignatureAlgorithm(provider, "RIPEMD160", "PLAIN-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecPlainDSARP160", BSIObjectIdentifiers.ecdsa_plain_RIPEMD160);
            this.addSignatureAlgorithm(provider, "SHA3-224", "PLAIN-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA3_224", BSIObjectIdentifiers.ecdsa_plain_SHA3_224);
            this.addSignatureAlgorithm(provider, "SHA3-256", "PLAIN-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA3_256", BSIObjectIdentifiers.ecdsa_plain_SHA3_256);
            this.addSignatureAlgorithm(provider, "SHA3-384", "PLAIN-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA3_384", BSIObjectIdentifiers.ecdsa_plain_SHA3_384);
            this.addSignatureAlgorithm(provider, "SHA3-512", "PLAIN-ECDSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA3_512", BSIObjectIdentifiers.ecdsa_plain_SHA3_512);
        }
    }
}