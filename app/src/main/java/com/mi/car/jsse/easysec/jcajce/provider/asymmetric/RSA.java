//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.jcajce.provider.asymmetric;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;
import com.mi.car.jsse.easysec.internal.asn1.cms.CMSObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.KeyFactorySpi;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter;
import java.util.HashMap;
import java.util.Map;

public class RSA {
    private static final String PREFIX = "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.";
    private static final Map<String, String> generalRsaAttributes = new HashMap();

    public RSA() {
    }

    static {
        generalRsaAttributes.put("SupportedKeyClasses", "javax.crypto.interfaces.RSAPublicKey|javax.crypto.interfaces.RSAPrivateKey");
        generalRsaAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings extends AsymmetricAlgorithmProvider {
        public Mappings() {
        }

        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("AlgorithmParameters.OAEP", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.AlgorithmParametersSpi$OAEP");
            provider.addAlgorithm("AlgorithmParameters.PSS", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.AlgorithmParametersSpi$PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.RSAPSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.RSASSA-PSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA224withRSA/PSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA256withRSA/PSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA384withRSA/PSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA512withRSA/PSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA224WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA256WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA384WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA512WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-224WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-256WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-384WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-512WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.RAWRSAPSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSAPSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSASSA-PSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSAANDMGF1", "PSS");
            provider.addAttributes("Cipher.RSA", RSA.generalRsaAttributes);
            provider.addAlgorithm("Cipher.RSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.CipherSpi$NoPadding");
            provider.addAlgorithm("Cipher.RSA/RAW", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.CipherSpi$NoPadding");
            provider.addAlgorithm("Cipher.RSA/PKCS1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.CipherSpi$PKCS1v1_5Padding");
            provider.addAlgorithm("Cipher", PKCSObjectIdentifiers.rsaEncryption, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.CipherSpi$PKCS1v1_5Padding");
            provider.addAlgorithm("Cipher", X509ObjectIdentifiers.id_ea_rsa, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.CipherSpi$PKCS1v1_5Padding");
            provider.addAlgorithm("Cipher.RSA/1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.CipherSpi$PKCS1v1_5Padding_PrivateOnly");
            provider.addAlgorithm("Cipher.RSA/2", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.CipherSpi$PKCS1v1_5Padding_PublicOnly");
            provider.addAlgorithm("Cipher.RSA/OAEP", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.CipherSpi$OAEPPadding");
            provider.addAlgorithm("Cipher", PKCSObjectIdentifiers.id_RSAES_OAEP, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.CipherSpi$OAEPPadding");
            provider.addAlgorithm("Cipher.RSA/ISO9796-1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.CipherSpi$ISO9796d1Padding");
            provider.addAlgorithm("Alg.Alias.Cipher.RSA//RAW", "RSA");
            provider.addAlgorithm("Alg.Alias.Cipher.RSA//NOPADDING", "RSA");
            provider.addAlgorithm("Alg.Alias.Cipher.RSA//PKCS1PADDING", "RSA/PKCS1");
            provider.addAlgorithm("Alg.Alias.Cipher.RSA//OAEPPADDING", "RSA/OAEP");
            provider.addAlgorithm("Alg.Alias.Cipher.RSA//ISO9796-1PADDING", "RSA/ISO9796-1");
            provider.addAlgorithm("KeyFactory.RSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.KeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.RSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi");
            provider.addAlgorithm("KeyFactory.RSASSA-PSS", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.KeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.RSASSA-PSS", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi$PSS");
            AsymmetricKeyInfoConverter keyFact = new KeyFactorySpi();
            this.registerOid(provider, PKCSObjectIdentifiers.rsaEncryption, "RSA", keyFact);
            this.registerOid(provider, X509ObjectIdentifiers.id_ea_rsa, "RSA", keyFact);
            this.registerOid(provider, PKCSObjectIdentifiers.id_RSAES_OAEP, "RSA", keyFact);
            this.registerOid(provider, PKCSObjectIdentifiers.id_RSASSA_PSS, "RSA", keyFact);
            this.registerOidAlgorithmParameters(provider, PKCSObjectIdentifiers.rsaEncryption, "RSA");
            this.registerOidAlgorithmParameters(provider, X509ObjectIdentifiers.id_ea_rsa, "RSA");
            this.registerOidAlgorithmParameters(provider, PKCSObjectIdentifiers.id_RSAES_OAEP, "OAEP");
            this.registerOidAlgorithmParameters(provider, PKCSObjectIdentifiers.id_RSASSA_PSS, "PSS");
            provider.addAlgorithm("Signature.RSASSA-PSS", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$PSSwithRSA");
            provider.addAlgorithm("Signature." + PKCSObjectIdentifiers.id_RSASSA_PSS, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$PSSwithRSA");
            provider.addAlgorithm("Signature.OID." + PKCSObjectIdentifiers.id_RSASSA_PSS, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$PSSwithRSA");
            provider.addAlgorithm("Signature.RSA", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$noneRSA");
            provider.addAlgorithm("Signature.RAWRSASSA-PSS", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$nonePSS");
            provider.addAlgorithm("Alg.Alias.Signature.RAWRSA", "RSA");
            provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSA", "RSA");
            provider.addAlgorithm("Alg.Alias.Signature.RAWRSAPSS", "RAWRSASSA-PSS");
            provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSAPSS", "RAWRSASSA-PSS");
            provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSASSA-PSS", "RAWRSASSA-PSS");
            provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSAANDMGF1", "RAWRSASSA-PSS");
            provider.addAlgorithm("Alg.Alias.Signature.RSAPSS", "RSASSA-PSS");
            this.addPSSSignature(provider, "SHA224", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA224withRSA");
            this.addPSSSignature(provider, "SHA256", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA256withRSA");
            this.addPSSSignature(provider, "SHA384", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA384withRSA");
            this.addPSSSignature(provider, "SHA512", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA512withRSA");
            this.addPSSSignature(provider, "SHA512(224)", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA512_224withRSA");
            this.addPSSSignature(provider, "SHA512(256)", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA512_256withRSA");
            this.addPSSSignature(provider, "SHA3-224", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_224withRSA");
            this.addPSSSignature(provider, "SHA3-256", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_256withRSA");
            this.addPSSSignature(provider, "SHA3-384", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_384withRSA");
            this.addPSSSignature(provider, "SHA3-512", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_512withRSA");
            this.addPSSSignature(provider, "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHAKE128WithRSAPSS", CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE128);
            this.addPSSSignature(provider, "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHAKE256WithRSAPSS", CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE256);
            this.addPSSSignature(provider, "SHA224", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA224withRSAandSHAKE128");
            this.addPSSSignature(provider, "SHA256", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA256withRSAandSHAKE128");
            this.addPSSSignature(provider, "SHA384", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA384withRSAandSHAKE128");
            this.addPSSSignature(provider, "SHA512", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA512withRSAandSHAKE128");
            this.addPSSSignature(provider, "SHA512(224)", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA512_224withRSAandSHAKE128");
            this.addPSSSignature(provider, "SHA512(256)", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA512_256withRSAandSHAKE128");
            this.addPSSSignature(provider, "SHA224", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA224withRSAandSHAKE256");
            this.addPSSSignature(provider, "SHA256", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA256withRSAandSHAKE256");
            this.addPSSSignature(provider, "SHA384", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA384withRSAandSHAKE256");
            this.addPSSSignature(provider, "SHA512", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA512withRSAandSHAKE256");
            this.addPSSSignature(provider, "SHA512(224)", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA512_224withRSAandSHAKE256");
            this.addPSSSignature(provider, "SHA512(256)", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA512_256withRSAandSHAKE256");
            this.addPSSSignature(provider, "SHA3-224", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_224withRSAandSHAKE128");
            this.addPSSSignature(provider, "SHA3-256", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_256withRSAandSHAKE128");
            this.addPSSSignature(provider, "SHA3-384", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_384withRSAandSHAKE128");
            this.addPSSSignature(provider, "SHA3-512", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_512withRSAandSHAKE128");
            this.addPSSSignature(provider, "SHA3-224", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_224withRSAandSHAKE256");
            this.addPSSSignature(provider, "SHA3-256", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_256withRSAandSHAKE256");
            this.addPSSSignature(provider, "SHA3-384", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_384withRSAandSHAKE256");
            this.addPSSSignature(provider, "SHA3-512", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA3_512withRSAandSHAKE256");
            if (provider.hasAlgorithm("MessageDigest", "MD2")) {
                this.addDigestSignature(provider, "MD2", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$MD2", PKCSObjectIdentifiers.md2WithRSAEncryption);
            }

            if (provider.hasAlgorithm("MessageDigest", "MD4")) {
                this.addDigestSignature(provider, "MD4", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$MD4", PKCSObjectIdentifiers.md4WithRSAEncryption);
            }

            if (provider.hasAlgorithm("MessageDigest", "MD5")) {
                this.addDigestSignature(provider, "MD5", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$MD5", PKCSObjectIdentifiers.md5WithRSAEncryption);
                this.addISO9796Signature(provider, "MD5", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$MD5WithRSAEncryption");
            }

            if (provider.hasAlgorithm("MessageDigest", "SHA1")) {
                provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA1withRSA/PSS", "PSS");
                provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA1WITHRSAANDMGF1", "PSS");
                this.addPSSSignature(provider, "SHA1", "MGF1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA1withRSA");
                this.addPSSSignature(provider, "SHA1", "SHAKE128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA1withRSAandSHAKE128");
                this.addPSSSignature(provider, "SHA1", "SHAKE256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA1withRSAandSHAKE256");
                this.addDigestSignature(provider, "SHA1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA1", PKCSObjectIdentifiers.sha1WithRSAEncryption);
                this.addISO9796Signature(provider, "SHA1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$SHA1WithRSAEncryption");
                provider.addAlgorithm("Alg.Alias.Signature." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
                provider.addAlgorithm("Alg.Alias.Signature.OID." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
                this.addX931Signature(provider, "SHA1", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$SHA1WithRSAEncryption");
            }

            this.addDigestSignature(provider, "SHA224", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA224", PKCSObjectIdentifiers.sha224WithRSAEncryption);
            this.addDigestSignature(provider, "SHA256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA256", PKCSObjectIdentifiers.sha256WithRSAEncryption);
            this.addDigestSignature(provider, "SHA384", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA384", PKCSObjectIdentifiers.sha384WithRSAEncryption);
            this.addDigestSignature(provider, "SHA512", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA512", PKCSObjectIdentifiers.sha512WithRSAEncryption);
            this.addDigestSignature(provider, "SHA512(224)", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA512_224", PKCSObjectIdentifiers.sha512_224WithRSAEncryption);
            this.addDigestSignature(provider, "SHA512(256)", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA512_256", PKCSObjectIdentifiers.sha512_256WithRSAEncryption);
            this.addDigestSignature(provider, "SHA3-224", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA3_224", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
            this.addDigestSignature(provider, "SHA3-256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA3_256", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
            this.addDigestSignature(provider, "SHA3-384", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA3_384", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
            this.addDigestSignature(provider, "SHA3-512", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA3_512", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);
            this.addISO9796Signature(provider, "SHA224", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$SHA224WithRSAEncryption");
            this.addISO9796Signature(provider, "SHA256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$SHA256WithRSAEncryption");
            this.addISO9796Signature(provider, "SHA384", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$SHA384WithRSAEncryption");
            this.addISO9796Signature(provider, "SHA512", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$SHA512WithRSAEncryption");
            this.addISO9796Signature(provider, "SHA512(224)", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$SHA512_224WithRSAEncryption");
            this.addISO9796Signature(provider, "SHA512(256)", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$SHA512_256WithRSAEncryption");
            this.addX931Signature(provider, "SHA224", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$SHA224WithRSAEncryption");
            this.addX931Signature(provider, "SHA256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$SHA256WithRSAEncryption");
            this.addX931Signature(provider, "SHA384", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$SHA384WithRSAEncryption");
            this.addX931Signature(provider, "SHA512", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$SHA512WithRSAEncryption");
            this.addX931Signature(provider, "SHA512(224)", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$SHA512_224WithRSAEncryption");
            this.addX931Signature(provider, "SHA512(256)", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$SHA512_256WithRSAEncryption");
            if (provider.hasAlgorithm("MessageDigest", "RIPEMD128")) {
                this.addDigestSignature(provider, "RIPEMD128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD128", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
                this.addDigestSignature(provider, "RMD128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD128", (ASN1ObjectIdentifier)null);
                this.addX931Signature(provider, "RMD128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$RIPEMD128WithRSAEncryption");
                this.addX931Signature(provider, "RIPEMD128", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$RIPEMD128WithRSAEncryption");
            }

            if (provider.hasAlgorithm("MessageDigest", "RIPEMD160")) {
                this.addDigestSignature(provider, "RIPEMD160", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD160", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
                this.addDigestSignature(provider, "RMD160", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD160", (ASN1ObjectIdentifier)null);
                provider.addAlgorithm("Alg.Alias.Signature.RIPEMD160WithRSA/ISO9796-2", "RIPEMD160withRSA/ISO9796-2");
                provider.addAlgorithm("Signature.RIPEMD160withRSA/ISO9796-2", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$RIPEMD160WithRSAEncryption");
                this.addX931Signature(provider, "RMD160", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$RIPEMD160WithRSAEncryption");
                this.addX931Signature(provider, "RIPEMD160", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$RIPEMD160WithRSAEncryption");
            }

            if (provider.hasAlgorithm("MessageDigest", "RIPEMD256")) {
                this.addDigestSignature(provider, "RIPEMD256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD256", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
                this.addDigestSignature(provider, "RMD256", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD256", (ASN1ObjectIdentifier)null);
            }

            if (provider.hasAlgorithm("MessageDigest", "WHIRLPOOL")) {
                this.addISO9796Signature(provider, "Whirlpool", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$WhirlpoolWithRSAEncryption");
                this.addISO9796Signature(provider, "WHIRLPOOL", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$WhirlpoolWithRSAEncryption");
                this.addX931Signature(provider, "Whirlpool", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$WhirlpoolWithRSAEncryption");
                this.addX931Signature(provider, "WHIRLPOOL", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.rsa.X931SignatureSpi$WhirlpoolWithRSAEncryption");
            }

        }

        private void addDigestSignature(ConfigurableProvider provider, String digest, String className, ASN1ObjectIdentifier oid) {
            String mainName = digest + "WITHRSA";
            String jdk11Variation1 = digest + "withRSA";
            String jdk11Variation2 = digest + "WithRSA";
            String alias = digest + "/RSA";
            String longName = digest + "WITHRSAENCRYPTION";
            String longJdk11Variation1 = digest + "withRSAEncryption";
            String longJdk11Variation2 = digest + "WithRSAEncryption";
            provider.addAlgorithm("Signature." + mainName, className);
            provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation1, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation2, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + longName, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + longJdk11Variation1, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + longJdk11Variation2, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + alias, mainName);
            if (oid != null) {
                provider.addAlgorithm("Alg.Alias.Signature." + oid, mainName);
                provider.addAlgorithm("Alg.Alias.Signature.OID." + oid, mainName);
            }

        }

        private void addISO9796Signature(ConfigurableProvider provider, String digest, String className) {
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSA/ISO9796-2", digest + "WITHRSA/ISO9796-2");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSA/ISO9796-2", digest + "WITHRSA/ISO9796-2");
            provider.addAlgorithm("Signature." + digest + "WITHRSA/ISO9796-2", className);
        }

        private void addPSSSignature(ConfigurableProvider provider, String digest, String mgf, String className) {
            String stem = "WITHRSAAND" + mgf;
            if (mgf.equals("MGF1")) {
                provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSA/PSS", digest + stem);
                provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSA/PSS", digest + stem);
                provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSASSA-PSS", digest + stem);
                provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSASSA-PSS", digest + stem);
                provider.addAlgorithm("Alg.Alias.Signature." + digest + "WITHRSASSA-PSS", digest + stem);
            }

            provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSAand" + mgf, digest + stem);
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSAAnd" + mgf, digest + stem);
            provider.addAlgorithm("Signature." + digest + "WITHRSAAND" + mgf, className);
        }

        private void addPSSSignature(ConfigurableProvider provider, String digest, String className, ASN1ObjectIdentifier sigOid) {
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSA/PSS", digest + "WITHRSAPSS");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSA/PSS", digest + "WITHRSAPSS");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSASSA-PSS", digest + "WITHRSAPSS");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSASSA-PSS", digest + "WITHRSAPSS");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WITHRSASSA-PSS", digest + "WITHRSAPSS");
            provider.addAlgorithm("Signature", sigOid, className);
            provider.addAlgorithm("Signature." + digest + "WITHRSAPSS", className);
        }

        private void addX931Signature(ConfigurableProvider provider, String digest, String className) {
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSA/X9.31", digest + "WITHRSA/X9.31");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSA/X9.31", digest + "WITHRSA/X9.31");
            provider.addAlgorithm("Signature." + digest + "WITHRSA/X9.31", className);
        }
    }
}