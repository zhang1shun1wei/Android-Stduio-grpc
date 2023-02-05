package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.edec.EdECObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.RSASSAPSSparams;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.KeyPurposeId;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.jsse.java.security.BCCryptoPrimitive;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCrypto;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

class ProvAlgorithmChecker extends PKIXCertPathChecker {
    private static final byte[] DER_NULL_ENCODING = {5, 0};
    static final int KU_DIGITAL_SIGNATURE = 0;
    static final int KU_KEY_AGREEMENT = 4;
    static final int KU_KEY_ENCIPHERMENT = 2;
    private static final String SIG_ALG_NAME_rsa_pss_pss_sha256 = JsseUtils.getJcaSignatureAlgorithmBC("SHA256withRSAandMGF1", "RSASSA-PSS");
    private static final String SIG_ALG_NAME_rsa_pss_pss_sha384 = JsseUtils.getJcaSignatureAlgorithmBC("SHA384withRSAandMGF1", "RSASSA-PSS");
    private static final String SIG_ALG_NAME_rsa_pss_pss_sha512 = JsseUtils.getJcaSignatureAlgorithmBC("SHA512withRSAandMGF1", "RSASSA-PSS");
    private static final String SIG_ALG_NAME_rsa_pss_rsae_sha256 = JsseUtils.getJcaSignatureAlgorithmBC("SHA256withRSAandMGF1", "RSA");
    private static final String SIG_ALG_NAME_rsa_pss_rsae_sha384 = JsseUtils.getJcaSignatureAlgorithmBC("SHA384withRSAandMGF1", "RSA");
    private static final String SIG_ALG_NAME_rsa_pss_rsae_sha512 = JsseUtils.getJcaSignatureAlgorithmBC("SHA512withRSAandMGF1", "RSA");
    private static final Map<String, String> sigAlgNames = createSigAlgNames();
    private static final Set<String> sigAlgNoParams = createSigAlgNoParams();
    private final BCAlgorithmConstraints algorithmConstraints;
    private final JcaJceHelper helper;
    private final boolean isInFipsMode;
    private X509Certificate issuerCert;

    private static Map<String, String> createSigAlgNames() {
        Map<String, String> names = new HashMap<>(4);
        names.put(EdECObjectIdentifiers.id_Ed25519.getId(), "Ed25519");
        names.put(EdECObjectIdentifiers.id_Ed448.getId(), "Ed448");
        names.put(OIWObjectIdentifiers.dsaWithSHA1.getId(), "SHA1withDSA");
        names.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), "SHA1withDSA");
        return Collections.unmodifiableMap(names);
    }

    private static Set<String> createSigAlgNoParams() {
        Set<String> noParams = new HashSet<>();
        noParams.add(OIWObjectIdentifiers.dsaWithSHA1.getId());
        noParams.add(X9ObjectIdentifiers.id_dsa_with_sha1.getId());
        noParams.add(PKCSObjectIdentifiers.id_RSASSA_PSS.getId());
        return Collections.unmodifiableSet(noParams);
    }

    ProvAlgorithmChecker(boolean isInFipsMode2, JcaJceHelper helper2, BCAlgorithmConstraints algorithmConstraints2) {
        if (helper2 == null) {
            throw new NullPointerException("'helper' cannot be null");
        } else if (algorithmConstraints2 == null) {
            throw new NullPointerException("'algorithmConstraints' cannot be null");
        } else {
            this.isInFipsMode = isInFipsMode2;
            this.helper = helper2;
            this.algorithmConstraints = algorithmConstraints2;
            this.issuerCert = null;
        }
    }

    @Override // java.security.cert.PKIXCertPathChecker, java.security.cert.CertPathChecker
    public void init(boolean forward) throws CertPathValidatorException {
        if (forward) {
            throw new CertPathValidatorException("forward checking not supported");
        }
        this.issuerCert = null;
    }

    public boolean isForwardCheckingSupported() {
        return false;
    }

    @Override // java.security.cert.PKIXCertPathChecker
    public Set<String> getSupportedExtensions() {
        return null;
    }

    @Override // java.security.cert.PKIXCertPathChecker, java.security.cert.CertPathChecker
    public void check(Certificate cert) throws CertPathValidatorException {
        check(cert, Collections.emptySet());
    }

    @Override // java.security.cert.PKIXCertPathChecker
    public void check(Certificate cert, Collection<String> collection) throws CertPathValidatorException {
        if (!(cert instanceof X509Certificate)) {
            throw new CertPathValidatorException("checker can only be used for X.509 certificates");
        }
        X509Certificate subjectCert = (X509Certificate) cert;
        if (!this.isInFipsMode || isValidFIPSPublicKey(subjectCert.getPublicKey())) {
            if (this.issuerCert != null) {
                checkIssuedBy(this.helper, this.algorithmConstraints, subjectCert, this.issuerCert);
            }
            this.issuerCert = subjectCert;
            return;
        }
        throw new CertPathValidatorException("non-FIPS public key found");
    }

    static void checkCertPathExtras(JcaJceHelper helper2, BCAlgorithmConstraints algorithmConstraints2, X509Certificate[] chain, KeyPurposeId ekuOID, int kuBit) throws CertPathValidatorException {
        X509Certificate taCert = chain[chain.length - 1];
        if (chain.length > 1) {
            checkIssuedBy(helper2, algorithmConstraints2, chain[chain.length - 2], taCert);
        }
        checkEndEntity(helper2, algorithmConstraints2, chain[0], ekuOID, kuBit);
    }

    static void checkChain(boolean isInFipsMode2, JcaJceHelper helper2, BCAlgorithmConstraints algorithmConstraints2, Set<X509Certificate> trustedCerts, X509Certificate[] chain, KeyPurposeId ekuOID, int kuBit) throws CertPathValidatorException {
        int taPos = chain.length;
        while (taPos > 0 && trustedCerts.contains(chain[taPos - 1])) {
            taPos--;
        }
        if (taPos < chain.length) {
            X509Certificate taCert = chain[taPos];
            if (taPos > 0) {
                checkIssuedBy(helper2, algorithmConstraints2, chain[taPos - 1], taCert);
            }
        } else {
            checkIssued(helper2, algorithmConstraints2, chain[taPos - 1]);
        }
        ProvAlgorithmChecker algorithmChecker = new ProvAlgorithmChecker(isInFipsMode2, helper2, algorithmConstraints2);
        algorithmChecker.init(false);
        for (int i = taPos - 1; i >= 0; i--) {
            algorithmChecker.check(chain[i], Collections.emptySet());
        }
        checkEndEntity(helper2, algorithmConstraints2, chain[0], ekuOID, kuBit);
    }

    private static void checkEndEntity(JcaJceHelper helper2, BCAlgorithmConstraints algorithmConstraints2, X509Certificate eeCert, KeyPurposeId ekuOID, int kuBit) throws CertPathValidatorException {
        if (ekuOID != null && !supportsExtendedKeyUsage(eeCert, ekuOID)) {
            throw new CertPathValidatorException("Certificate doesn't support '" + getExtendedKeyUsageName(ekuOID) + "' ExtendedKeyUsage");
        } else if (kuBit < 0) {
        } else {
            if (!supportsKeyUsage(eeCert, kuBit)) {
                throw new CertPathValidatorException("Certificate doesn't support '" + getKeyUsageName(kuBit) + "' KeyUsage");
            } else if (!algorithmConstraints2.permits(getKeyUsagePrimitives(kuBit), eeCert.getPublicKey())) {
                throw new CertPathValidatorException("Public key not permitted for '" + getKeyUsageName(kuBit) + "' KeyUsage");
            }
        }
    }

    private static void checkIssued(JcaJceHelper helper2, BCAlgorithmConstraints algorithmConstraints2, X509Certificate cert) throws CertPathValidatorException {
        String sigAlgName = getSigAlgName(cert, null);
        if (!JsseUtils.isNameSpecified(sigAlgName)) {
            throw new CertPathValidatorException("Signature algorithm could not be determined");
        }
        if (!algorithmConstraints2.permits(JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC, sigAlgName, getSigAlgParams(helper2, cert))) {
            throw new CertPathValidatorException("Signature algorithm '" + sigAlgName + "' not permitted with given parameters");
        }
    }

    private static void checkIssuedBy(JcaJceHelper helper2, BCAlgorithmConstraints algorithmConstraints2, X509Certificate subjectCert, X509Certificate issuerCert2) throws CertPathValidatorException {
        String sigAlgName = getSigAlgName(subjectCert, issuerCert2);
        if (!JsseUtils.isNameSpecified(sigAlgName)) {
            throw new CertPathValidatorException("Signature algorithm could not be determined");
        }
        if (!algorithmConstraints2.permits(JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC, sigAlgName, issuerCert2.getPublicKey(), getSigAlgParams(helper2, subjectCert))) {
            throw new CertPathValidatorException("Signature algorithm '" + sigAlgName + "' not permitted with given parameters and issuer public key");
        }
    }

    static String getExtendedKeyUsageName(KeyPurposeId ekuOID) {
        if (KeyPurposeId.id_kp_clientAuth.equals(ekuOID)) {
            return "clientAuth";
        }
        if (KeyPurposeId.id_kp_serverAuth.equals(ekuOID)) {
            return "serverAuth";
        }
        return "(" + ekuOID + ")";
    }

    static String getKeyUsageName(int kuBit) {
        switch (kuBit) {
            case 0:
                return "digitalSignature";
            case 1:
            case 3:
            default:
                return "(" + kuBit + ")";
            case 2:
                return "keyEncipherment";
            case 4:
                return "keyAgreement";
        }
    }

    static Set<BCCryptoPrimitive> getKeyUsagePrimitives(int kuBit) {
        switch (kuBit) {
            case 2:
                return JsseUtils.KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC;
            case 3:
            default:
                return JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC;
            case 4:
                return JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;
        }
    }

    static String getSigAlgName(X509Certificate subjectCert, X509Certificate issuerCert2) {
        ASN1ObjectIdentifier hashOID;
        String sigAlgOID = subjectCert.getSigAlgOID();
        String sigAlgName = sigAlgNames.get(sigAlgOID);
        if (sigAlgName != null) {
            return sigAlgName;
        }
        if (!PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(sigAlgOID)) {
            return subjectCert.getSigAlgName();
        }
        RSASSAPSSparams pssParams = RSASSAPSSparams.getInstance(subjectCert.getSigAlgParams());
        if (!(pssParams == null || (hashOID = pssParams.getHashAlgorithm().getAlgorithm()) == null)) {
            X509Certificate keyCert = issuerCert2;
            if (keyCert == null) {
                keyCert = subjectCert;
            }
            try {
                JcaTlsCertificate jcaKeyCert = new JcaTlsCertificate((JcaTlsCrypto) null, keyCert);
                if (NISTObjectIdentifiers.id_sha256.equals(hashOID)) {
                    if (jcaKeyCert.supportsSignatureAlgorithmCA((short) 9)) {
                        return SIG_ALG_NAME_rsa_pss_pss_sha256;
                    }
                    if (jcaKeyCert.supportsSignatureAlgorithmCA((short) 4)) {
                        return SIG_ALG_NAME_rsa_pss_rsae_sha256;
                    }
                } else if (NISTObjectIdentifiers.id_sha384.equals(hashOID)) {
                    if (jcaKeyCert.supportsSignatureAlgorithmCA((short) 10)) {
                        return SIG_ALG_NAME_rsa_pss_pss_sha384;
                    }
                    if (jcaKeyCert.supportsSignatureAlgorithmCA((short) 5)) {
                        return SIG_ALG_NAME_rsa_pss_rsae_sha384;
                    }
                } else if (NISTObjectIdentifiers.id_sha512.equals(hashOID)) {
                    if (jcaKeyCert.supportsSignatureAlgorithmCA((short) 11)) {
                        return SIG_ALG_NAME_rsa_pss_pss_sha512;
                    }
                    if (jcaKeyCert.supportsSignatureAlgorithmCA((short) 6)) {
                        return SIG_ALG_NAME_rsa_pss_rsae_sha512;
                    }
                }
            } catch (IOException e) {
            }
        }
        return null;
    }

    static AlgorithmParameters getSigAlgParams(JcaJceHelper helper2, X509Certificate cert) throws CertPathValidatorException {
        AlgorithmParameters sigAlgParams = null;
        byte[] encoded = cert.getSigAlgParams();
        if (encoded != null) {
            String sigAlgOID = cert.getSigAlgOID();
            if (!sigAlgNoParams.contains(sigAlgOID) || !Arrays.areEqual(DER_NULL_ENCODING, encoded)) {
                try {
                    sigAlgParams = helper2.createAlgorithmParameters(sigAlgOID);
                    try {
                        sigAlgParams.init(encoded);
                    } catch (Exception e) {
                        throw new CertPathValidatorException(e);
                    }
                } catch (GeneralSecurityException e2) {
                }
            }
        }
        return sigAlgParams;
    }

    static boolean isValidFIPSPublicKey(PublicKey publicKey) {
        try {
            AlgorithmIdentifier algID = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm();
            if (!X9ObjectIdentifiers.id_ecPublicKey.equals(algID.getAlgorithm())) {
                return true;
            }
            ASN1Encodable parameters = algID.getParameters();
            if (parameters == null || !(parameters.toASN1Primitive() instanceof ASN1ObjectIdentifier)) {
                return false;
            }
            return true;
        } catch (Exception e) {
        }
        return false;
    }

    static boolean permitsKeyUsage(PublicKey publicKey, boolean[] ku, int kuBit, BCAlgorithmConstraints algorithmConstraints2) {
        return supportsKeyUsage(ku, kuBit) && algorithmConstraints2.permits(getKeyUsagePrimitives(kuBit), publicKey);
    }

    static boolean supportsExtendedKeyUsage(X509Certificate cert, KeyPurposeId ekuOID) {
        try {
            return supportsExtendedKeyUsage(cert.getExtendedKeyUsage(), ekuOID);
        } catch (CertificateParsingException e) {
            return false;
        }
    }

    static boolean supportsExtendedKeyUsage(List<String> eku, KeyPurposeId ekuOID) {
        return eku == null || eku.contains(ekuOID.getId()) || eku.contains(KeyPurposeId.anyExtendedKeyUsage.getId());
    }

    static boolean supportsKeyUsage(X509Certificate cert, int kuBit) {
        return supportsKeyUsage(cert.getKeyUsage(), kuBit);
    }

    static boolean supportsKeyUsage(boolean[] ku, int kuBit) {
        return ku == null || (ku.length > kuBit && ku[kuBit]);
    }
}
