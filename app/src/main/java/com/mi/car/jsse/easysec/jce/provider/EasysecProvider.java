//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.bc.BCObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.isara.IsaraObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.config.ProviderConfiguration;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.ClassUtil;
import com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.lms.LMSKeyFactorySpi;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceCCA2KeyFactorySpi;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece.McElieceKeyFactorySpi;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.newhope.NHKeyFactorySpi;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla.QTESLAKeyFactorySpi;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow.RainbowKeyFactorySpi;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs.Sphincs256KeyFactorySpi;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSKeyFactorySpi;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss.XMSSMTKeyFactorySpi;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public final class EasysecProvider extends Provider implements ConfigurableProvider {
    private static String info = "BouncyCastle Security Provider v1.71";
    public static final String PROVIDER_NAME = "ES";
    public static final ProviderConfiguration CONFIGURATION = new EasysecProviderConfiguration();
    private static final Map keyInfoConverters = new HashMap();
    private static final Class revChkClass = ClassUtil.loadClass(EasysecProvider.class, "java.security.cert.PKIXRevocationChecker");
    private static final String SYMMETRIC_PACKAGE = "com.mi.car.jsse.easysec.jcajce.provider.symmetric.";
    private static final String[] SYMMETRIC_GENERIC = new String[]{"PBEPBKDF1", "PBEPBKDF2", "PBEPKCS12", "TLSKDF", "SCRYPT"};
    private static final String[] SYMMETRIC_MACS = new String[]{"SipHash", "SipHash128", "Poly1305"};
    private static final String[] SYMMETRIC_CIPHERS = new String[]{"AES", "ARC4", "ARIA", "Blowfish", "Camellia", "CAST5", "CAST6", "ChaCha", "DES", "DESede", "GOST28147", "Grainv1", "Grain128", "HC128", "HC256", "IDEA", "Noekeon", "RC2", "RC5", "RC6", "Rijndael", "Salsa20", "SEED", "Serpent", "Shacal2", "Skipjack", "SM4", "TEA", "Twofish", "Threefish", "VMPC", "VMPCKSA3", "XTEA", "XSalsa20", "OpenSSLPBKDF", "DSTU7624", "GOST3412_2015", "Zuc"};
    private static final String ASYMMETRIC_PACKAGE = "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.";
    private static final String[] ASYMMETRIC_GENERIC = new String[]{"X509", "IES", "COMPOSITE", "EXTERNAL"};
    private static final String[] ASYMMETRIC_CIPHERS = new String[]{"DSA", "DH", "EC", "RSA", "GOST", "ECGOST", "ElGamal", "DSTU4145", "GM", "EdEC", "LMS", "SPHINCSPlus"};
    private static final String DIGEST_PACKAGE = "com.mi.car.jsse.easysec.jcajce.provider.digest.";
    private static final String[] DIGESTS = new String[]{"GOST3411", "Keccak", "MD2", "MD4", "MD5", "SHA1", "RIPEMD128", "RIPEMD160", "RIPEMD256", "RIPEMD320", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3", "Skein", "SM3", "Tiger", "Whirlpool", "Blake2b", "Blake2s", "DSTU7564", "Haraka", "Blake3"};
    private static final String KEYSTORE_PACKAGE = "com.mi.car.jsse.easysec.jcajce.provider.keystore.";
    private static final String[] KEYSTORES = new String[]{"BC", "BCFKS", "PKCS12"};
    private static final String SECURE_RANDOM_PACKAGE = "com.mi.car.jsse.easysec.jcajce.provider.drbg.";
    private static final String[] SECURE_RANDOMS = new String[]{"DRBG"};

    public EasysecProvider() {
        super("ES", 1.71D, info);
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                EasysecProvider.this.setup();
                return null;
            }
        });
    }

    private void setup() {
        this.loadAlgorithms("com.mi.car.jsse.easysec.jcajce.provider.digest.", DIGESTS);
        this.loadAlgorithms("com.mi.car.jsse.easysec.jcajce.provider.symmetric.", SYMMETRIC_GENERIC);
        this.loadAlgorithms("com.mi.car.jsse.easysec.jcajce.provider.symmetric.", SYMMETRIC_MACS);
        this.loadAlgorithms("com.mi.car.jsse.easysec.jcajce.provider.symmetric.", SYMMETRIC_CIPHERS);
        this.loadAlgorithms("com.mi.car.jsse.easysec.jcajce.provider.asymmetric.", ASYMMETRIC_GENERIC);
        this.loadAlgorithms("com.mi.car.jsse.easysec.jcajce.provider.asymmetric.", ASYMMETRIC_CIPHERS);
        this.loadAlgorithms("com.mi.car.jsse.easysec.jcajce.provider.keystore.", KEYSTORES);
        this.loadAlgorithms("com.mi.car.jsse.easysec.jcajce.provider.drbg.", SECURE_RANDOMS);
        this.loadPQCKeys();
        this.put("X509Store.CERTIFICATE/COLLECTION", "com.mi.car.jsse.easysec.jce.provider.X509StoreCertCollection");
        this.put("X509Store.ATTRIBUTECERTIFICATE/COLLECTION", "com.mi.car.jsse.easysec.jce.provider.X509StoreAttrCertCollection");
        this.put("X509Store.CRL/COLLECTION", "com.mi.car.jsse.easysec.jce.provider.X509StoreCRLCollection");
        this.put("X509Store.CERTIFICATEPAIR/COLLECTION", "com.mi.car.jsse.easysec.jce.provider.X509StoreCertPairCollection");
        this.put("X509Store.CERTIFICATE/LDAP", "com.mi.car.jsse.easysec.jce.provider.X509StoreLDAPCerts");
        this.put("X509Store.CRL/LDAP", "com.mi.car.jsse.easysec.jce.provider.X509StoreLDAPCRLs");
        this.put("X509Store.ATTRIBUTECERTIFICATE/LDAP", "com.mi.car.jsse.easysec.jce.provider.X509StoreLDAPAttrCerts");
        this.put("X509Store.CERTIFICATEPAIR/LDAP", "com.mi.car.jsse.easysec.jce.provider.X509StoreLDAPCertPairs");
        this.put("X509StreamParser.CERTIFICATE", "com.mi.car.jsse.easysec.jce.provider.X509CertParser");
        this.put("X509StreamParser.ATTRIBUTECERTIFICATE", "com.mi.car.jsse.easysec.jce.provider.X509AttrCertParser");
        this.put("X509StreamParser.CRL", "com.mi.car.jsse.easysec.jce.provider.X509CRLParser");
        this.put("X509StreamParser.CERTIFICATEPAIR", "com.mi.car.jsse.easysec.jce.provider.X509CertPairParser");
        this.put("Cipher.BROKENPBEWITHMD5ANDDES", "com.mi.car.jsse.easysec.jce.provider.BrokenJCEBlockCipher$BrokePBEWithMD5AndDES");
        this.put("Cipher.BROKENPBEWITHSHA1ANDDES", "com.mi.car.jsse.easysec.jce.provider.BrokenJCEBlockCipher$BrokePBEWithSHA1AndDES");
        this.put("Cipher.OLDPBEWITHSHAANDTWOFISH-CBC", "com.mi.car.jsse.easysec.jce.provider.BrokenJCEBlockCipher$OldPBEWithSHAAndTwofish");
        if (revChkClass != null) {
            this.put("CertPathValidator.RFC3281", "com.mi.car.jsse.easysec.jce.provider.PKIXAttrCertPathValidatorSpi");
            this.put("CertPathBuilder.RFC3281", "com.mi.car.jsse.easysec.jce.provider.PKIXAttrCertPathBuilderSpi");
            this.put("CertPathValidator.RFC3280", "com.mi.car.jsse.easysec.jce.provider.PKIXCertPathValidatorSpi_8");
            this.put("CertPathBuilder.RFC3280", "com.mi.car.jsse.easysec.jce.provider.PKIXCertPathBuilderSpi_8");
            this.put("CertPathValidator.PKIX", "com.mi.car.jsse.easysec.jce.provider.PKIXCertPathValidatorSpi_8");
            this.put("CertPathBuilder.PKIX", "com.mi.car.jsse.easysec.jce.provider.PKIXCertPathBuilderSpi_8");
        } else {
            this.put("CertPathValidator.RFC3281", "com.mi.car.jsse.easysec.jce.provider.PKIXAttrCertPathValidatorSpi");
            this.put("CertPathBuilder.RFC3281", "com.mi.car.jsse.easysec.jce.provider.PKIXAttrCertPathBuilderSpi");
            this.put("CertPathValidator.RFC3280", "com.mi.car.jsse.easysec.jce.provider.PKIXCertPathValidatorSpi");
            this.put("CertPathBuilder.RFC3280", "com.mi.car.jsse.easysec.jce.provider.PKIXCertPathBuilderSpi");
            this.put("CertPathValidator.PKIX", "com.mi.car.jsse.easysec.jce.provider.PKIXCertPathValidatorSpi");
            this.put("CertPathBuilder.PKIX", "com.mi.car.jsse.easysec.jce.provider.PKIXCertPathBuilderSpi");
        }

        this.put("CertStore.Collection", "com.mi.car.jsse.easysec.jce.provider.CertStoreCollectionSpi");
        this.put("CertStore.LDAP", "com.mi.car.jsse.easysec.jce.provider.X509LDAPCertStoreSpi");
        this.put("CertStore.Multi", "com.mi.car.jsse.easysec.jce.provider.MultiCertStoreSpi");
        this.put("Alg.Alias.CertStore.X509LDAP", "LDAP");
    }

    private void loadAlgorithms(String packageName, String[] names) {
        for(int i = 0; i != names.length; ++i) {
            Class clazz = ClassUtil.loadClass(EasysecProvider.class, packageName + names[i] + "$Mappings");
            if (clazz != null) {
                try {
                    ((AlgorithmProvider)clazz.newInstance()).configure(this);
                } catch (Exception var6) {
                    throw new InternalError("cannot create instance of " + packageName + names[i] + "$Mappings : " + var6);
                }
            }
        }

    }

    private void loadPQCKeys() {
        this.addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus, new SPHINCSPlusKeyFactorySpi());
        this.addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_256, new SPHINCSPlusKeyFactorySpi());
        this.addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha_256, new SPHINCSPlusKeyFactorySpi());
        this.addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha_512, new SPHINCSPlusKeyFactorySpi());
        this.addKeyInfoConverter(PQCObjectIdentifiers.sphincs256, new Sphincs256KeyFactorySpi());
        this.addKeyInfoConverter(PQCObjectIdentifiers.newHope, new NHKeyFactorySpi());
        this.addKeyInfoConverter(PQCObjectIdentifiers.xmss, new XMSSKeyFactorySpi());
        this.addKeyInfoConverter(IsaraObjectIdentifiers.id_alg_xmss, new XMSSKeyFactorySpi());
        this.addKeyInfoConverter(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyFactorySpi());
        this.addKeyInfoConverter(IsaraObjectIdentifiers.id_alg_xmssmt, new XMSSMTKeyFactorySpi());
        this.addKeyInfoConverter(PQCObjectIdentifiers.mcEliece, new McElieceKeyFactorySpi());
        this.addKeyInfoConverter(PQCObjectIdentifiers.mcElieceCca2, new McElieceCCA2KeyFactorySpi());
        this.addKeyInfoConverter(PQCObjectIdentifiers.rainbow, new RainbowKeyFactorySpi());
        this.addKeyInfoConverter(PQCObjectIdentifiers.qTESLA_p_I, new QTESLAKeyFactorySpi());
        this.addKeyInfoConverter(PQCObjectIdentifiers.qTESLA_p_III, new QTESLAKeyFactorySpi());
        this.addKeyInfoConverter(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, new LMSKeyFactorySpi());
    }

    public void setParameter(String parameterName, Object parameter) {
        synchronized(CONFIGURATION) {
            ((EasysecProviderConfiguration)CONFIGURATION).setParameter(parameterName, parameter);
        }
    }

    public boolean hasAlgorithm(String type, String name) {
        return this.containsKey(type + "." + name) || this.containsKey("Alg.Alias." + type + "." + name);
    }

    public void addAlgorithm(String key, String value) {
        if (this.containsKey(key)) {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        } else {
            this.put(key, value);
        }
    }

    public void addAlgorithm(String type, ASN1ObjectIdentifier oid, String className) {
        this.addAlgorithm(type + "." + oid, className);
        this.addAlgorithm(type + ".OID." + oid, className);
    }

    public void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter) {
        synchronized(keyInfoConverters) {
            keyInfoConverters.put(oid, keyInfoConverter);
        }
    }

    public AsymmetricKeyInfoConverter getKeyInfoConverter(ASN1ObjectIdentifier oid) {
        return (AsymmetricKeyInfoConverter)keyInfoConverters.get(oid);
    }

    public void addAttributes(String key, Map<String, String> attributeMap) {
        Iterator it = attributeMap.keySet().iterator();

        while(it.hasNext()) {
            String attributeName = (String)it.next();
            String attributeKey = key + " " + attributeName;
            if (this.containsKey(attributeKey)) {
                throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
            }

            this.put(attributeKey, attributeMap.get(attributeName));
        }

    }

    private static AsymmetricKeyInfoConverter getAsymmetricKeyInfoConverter(ASN1ObjectIdentifier algorithm) {
        synchronized(keyInfoConverters) {
            return (AsymmetricKeyInfoConverter)keyInfoConverters.get(algorithm);
        }
    }

    public static PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo) throws IOException {
        AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(publicKeyInfo.getAlgorithm().getAlgorithm());
        return converter == null ? null : converter.generatePublic(publicKeyInfo);
    }

    public static PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo) throws IOException {
        AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());
        return converter == null ? null : converter.generatePrivate(privateKeyInfo);
    }
}