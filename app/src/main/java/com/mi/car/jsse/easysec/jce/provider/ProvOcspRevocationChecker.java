package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1String;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.isara.IsaraObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.ocsp.BasicOCSPResponse;
import com.mi.car.jsse.easysec.asn1.ocsp.CertID;
import com.mi.car.jsse.easysec.asn1.ocsp.OCSPObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.ocsp.OCSPResponse;
import com.mi.car.jsse.easysec.asn1.ocsp.ResponderID;
import com.mi.car.jsse.easysec.asn1.ocsp.ResponseBytes;
import com.mi.car.jsse.easysec.asn1.ocsp.ResponseData;
import com.mi.car.jsse.easysec.asn1.ocsp.RevokedInfo;
import com.mi.car.jsse.easysec.asn1.ocsp.SingleResponse;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.RSASSAPSSparams;
import com.mi.car.jsse.easysec.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x500.style.BCStrictStyle;
import com.mi.car.jsse.easysec.asn1.x509.AccessDescription;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.AuthorityInformationAccess;
import com.mi.car.jsse.easysec.asn1.x509.CRLReason;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import com.mi.car.jsse.easysec.asn1.x509.KeyPurposeId;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.internal.asn1.bsi.BSIObjectIdentifiers;
import com.mi.car.jsse.easysec.internal.asn1.eac.EACObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker;
import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationCheckerParameters;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jcajce.util.MessageDigestUtils;
import com.mi.car.jsse.easysec.jce.exception.ExtCertPathValidatorException;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Properties;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

class ProvOcspRevocationChecker implements PKIXCertRevocationChecker {
    private static final int DEFAULT_OCSP_TIMEOUT = 15000;
    private static final int DEFAULT_OCSP_MAX_RESPONSE_SIZE = 32768;
    private static final Map oids = new HashMap();
    private final ProvRevocationChecker parent;
    private final JcaJceHelper helper;
    private PKIXCertRevocationCheckerParameters parameters;
    private boolean isEnabledOCSP;
    private String ocspURL;

    public ProvOcspRevocationChecker(ProvRevocationChecker parent, JcaJceHelper helper) {
        this.parent = parent;
        this.helper = helper;
    }

    public void setParameter(String name, Object value) {
    }

    public void initialize(PKIXCertRevocationCheckerParameters parameters) {
        this.parameters = parameters;
        this.isEnabledOCSP = Properties.isOverrideSet("ocsp.enable");
        this.ocspURL = Properties.getPropertyValue("ocsp.responderURL");
    }

    public List<CertPathValidatorException> getSoftFailExceptions() {
        return null;
    }

    public void init(boolean forForward) throws CertPathValidatorException {
        if (forForward) {
            throw new CertPathValidatorException("forward checking not supported");
        } else {
            this.parameters = null;
            this.isEnabledOCSP = Properties.isOverrideSet("ocsp.enable");
            this.ocspURL = Properties.getPropertyValue("ocsp.responderURL");
        }
    }

    public boolean isForwardCheckingSupported() {
        return false;
    }

    public Set<String> getSupportedExtensions() {
        return null;
    }

    public void check(Certificate certificate) throws CertPathValidatorException {
        X509Certificate cert = (X509Certificate)certificate;
        Map<X509Certificate, byte[]> ocspResponses = this.parent.getOcspResponses();
        URI ocspUri = this.parent.getOcspResponder();
        if (ocspUri == null) {
            if (this.ocspURL != null) {
                try {
                    ocspUri = new URI(this.ocspURL);
                } catch (URISyntaxException var20) {
                    throw new CertPathValidatorException("configuration error: " + var20.getMessage(), var20, this.parameters.getCertPath(), this.parameters.getIndex());
                }
            } else {
                ocspUri = getOcspResponderURI(cert);
            }
        }

        byte[] nonce = null;
        boolean preValidated = false;
        if (ocspResponses.get(cert) == null && ocspUri != null) {
            if (this.ocspURL == null && this.parent.getOcspResponder() == null && !this.isEnabledOCSP) {
                throw new RecoverableCertPathValidatorException("OCSP disabled by \"ocsp.enable\" setting", (Throwable)null, this.parameters.getCertPath(), this.parameters.getIndex());
            }

            com.mi.car.jsse.easysec.asn1.x509.Certificate issuer = this.extractCert();
            CertID id = this.createCertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), issuer, new ASN1Integer(cert.getSerialNumber()));
            OCSPResponse response = OcspCache.getOcspResponse(id, this.parameters, ocspUri, this.parent.getOcspResponderCert(), this.parent.getOcspExtensions(), this.helper);

            try {
                ocspResponses.put(cert, response.getEncoded());
                preValidated = true;
            } catch (IOException var19) {
                throw new CertPathValidatorException("unable to encode OCSP response", var19, this.parameters.getCertPath(), this.parameters.getIndex());
            }
        } else {
            List exts = this.parent.getOcspExtensions();

            for(int i = 0; i != exts.size(); ++i) {
                Extension ext = (Extension)exts.get(i);
                byte[] value = ext.getValue();
                if (OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId().equals(ext.getId())) {
                    nonce = value;
                }
            }
        }

        if (ocspResponses.isEmpty()) {
            throw new RecoverableCertPathValidatorException("no OCSP response found for any certificate", (Throwable)null, this.parameters.getCertPath(), this.parameters.getIndex());
        } else {
            OCSPResponse ocspResponse = OCSPResponse.getInstance(ocspResponses.get(cert));
            ASN1Integer serialNumber = new ASN1Integer(cert.getSerialNumber());
            if (ocspResponse != null) {
                if (0 != ocspResponse.getResponseStatus().getIntValue()) {
                    throw new CertPathValidatorException("OCSP response failed: " + ocspResponse.getResponseStatus().getValue(), (Throwable)null, this.parameters.getCertPath(), this.parameters.getIndex());
                } else {
                    ResponseBytes respBytes = ResponseBytes.getInstance(ocspResponse.getResponseBytes());
                    if (respBytes.getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
                        try {
                            BasicOCSPResponse basicResp = BasicOCSPResponse.getInstance(respBytes.getResponse().getOctets());
                            if (preValidated || validatedOcspResponse(basicResp, this.parameters, nonce, this.parent.getOcspResponderCert(), this.helper)) {
                                ResponseData responseData = ResponseData.getInstance(basicResp.getTbsResponseData());
                                ASN1Sequence s = responseData.getResponses();
                                CertID certID = null;

                                for(int i = 0; i != s.size(); ++i) {
                                    SingleResponse resp = SingleResponse.getInstance(s.getObjectAt(i));
                                    if (serialNumber.equals(resp.getCertID().getSerialNumber())) {
                                        ASN1GeneralizedTime nextUp = resp.getNextUpdate();
                                        if (nextUp != null && this.parameters.getValidDate().after(nextUp.getDate())) {
                                            throw new ExtCertPathValidatorException("OCSP response expired");
                                        }

                                        if (certID == null || !certID.getHashAlgorithm().equals(resp.getCertID().getHashAlgorithm())) {
                                            com.mi.car.jsse.easysec.asn1.x509.Certificate issuer = this.extractCert();
                                            certID = this.createCertID(resp.getCertID(), issuer, serialNumber);
                                        }

                                        if (certID.equals(resp.getCertID())) {
                                            if (resp.getCertStatus().getTagNo() == 0) {
                                                return;
                                            }

                                            if (resp.getCertStatus().getTagNo() == 1) {
                                                RevokedInfo info = RevokedInfo.getInstance(resp.getCertStatus().getStatus());
                                                CRLReason reason = info.getRevocationReason();
                                                throw new CertPathValidatorException("certificate revoked, reason=(" + reason + "), date=" + info.getRevocationTime().getDate(), (Throwable)null, this.parameters.getCertPath(), this.parameters.getIndex());
                                            }

                                            throw new CertPathValidatorException("certificate revoked, details unknown", (Throwable)null, this.parameters.getCertPath(), this.parameters.getIndex());
                                        }
                                    }
                                }
                            }
                        } catch (CertPathValidatorException var21) {
                            throw var21;
                        } catch (Exception var22) {
                            throw new CertPathValidatorException("unable to process OCSP response", var22, this.parameters.getCertPath(), this.parameters.getIndex());
                        }
                    }

                }
            } else {
                throw new RecoverableCertPathValidatorException("no OCSP response found for certificate", (Throwable)null, this.parameters.getCertPath(), this.parameters.getIndex());
            }
        }
    }

    static URI getOcspResponderURI(X509Certificate cert) {
        byte[] extValue = cert.getExtensionValue(com.mi.car.jsse.easysec.asn1.x509.Extension.authorityInfoAccess.getId());
        if (extValue == null) {
            return null;
        } else {
            AuthorityInformationAccess aiAccess = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(extValue).getOctets());
            AccessDescription[] descriptions = aiAccess.getAccessDescriptions();

            for(int i = 0; i != descriptions.length; ++i) {
                AccessDescription aDesc = descriptions[i];
                if (AccessDescription.id_ad_ocsp.equals(aDesc.getAccessMethod())) {
                    GeneralName name = aDesc.getAccessLocation();
                    if (name.getTagNo() == 6) {
                        try {
                            return new URI(((ASN1String)name.getName()).getString());
                        } catch (URISyntaxException var8) {
                        }
                    }
                }
            }

            return null;
        }
    }

    static boolean validatedOcspResponse(BasicOCSPResponse basicResp, PKIXCertRevocationCheckerParameters parameters, byte[] nonce, X509Certificate responderCert, JcaJceHelper helper) throws CertPathValidatorException {
        try {
            ASN1Sequence certs = basicResp.getCerts();
            Signature sig = helper.createSignature(getSignatureName(basicResp.getSignatureAlgorithm()));
            X509Certificate sigCert = getSignerCert(basicResp, parameters.getSigningCert(), responderCert, helper);
            if (sigCert == null && certs == null) {
                throw new CertPathValidatorException("OCSP responder certificate not found");
            } else {
                if (sigCert != null) {
                    sig.initVerify(sigCert.getPublicKey());
                } else {
                    CertificateFactory cf = helper.createCertificateFactory("X.509");
                    X509Certificate ocspCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certs.getObjectAt(0).toASN1Primitive().getEncoded()));
                    ocspCert.verify(parameters.getSigningCert().getPublicKey());
                    ocspCert.checkValidity(parameters.getValidDate());
                    if (!responderMatches(basicResp.getTbsResponseData().getResponderID(), ocspCert, helper)) {
                        throw new CertPathValidatorException("responder certificate does not match responderID", (Throwable)null, parameters.getCertPath(), parameters.getIndex());
                    }

                    List extendedKeyUsage = ocspCert.getExtendedKeyUsage();
                    if (extendedKeyUsage == null || !extendedKeyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
                        throw new CertPathValidatorException("responder certificate not valid for signing OCSP responses", (Throwable)null, parameters.getCertPath(), parameters.getIndex());
                    }

                    sig.initVerify(ocspCert);
                }

                sig.update(basicResp.getTbsResponseData().getEncoded("DER"));
                if (sig.verify(basicResp.getSignature().getBytes())) {
                    if (nonce != null) {
                        Extensions exts = basicResp.getTbsResponseData().getResponseExtensions();
                        com.mi.car.jsse.easysec.asn1.x509.Extension ext = exts.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                        if (!Arrays.areEqual(nonce, ext.getExtnValue().getOctets())) {
                            throw new CertPathValidatorException("nonce mismatch in OCSP response", (Throwable)null, parameters.getCertPath(), parameters.getIndex());
                        }
                    }

                    return true;
                } else {
                    return false;
                }
            }
        } catch (CertPathValidatorException var11) {
            throw var11;
        } catch (GeneralSecurityException var12) {
            throw new CertPathValidatorException("OCSP response failure: " + var12.getMessage(), var12, parameters.getCertPath(), parameters.getIndex());
        } catch (IOException var13) {
            throw new CertPathValidatorException("OCSP response failure: " + var13.getMessage(), var13, parameters.getCertPath(), parameters.getIndex());
        }
    }

    private static X509Certificate getSignerCert(BasicOCSPResponse basicResp, X509Certificate signingCert, X509Certificate responderCert, JcaJceHelper helper) throws NoSuchProviderException, NoSuchAlgorithmException {
        ResponderID responderID = basicResp.getTbsResponseData().getResponderID();
        byte[] keyHash = responderID.getKeyHash();
        if (keyHash != null) {
            MessageDigest digest = helper.createMessageDigest("SHA1");
            if (responderCert != null && Arrays.areEqual(keyHash, calcKeyHash(digest, responderCert.getPublicKey()))) {
                return responderCert;
            }

            if (signingCert != null && Arrays.areEqual(keyHash, calcKeyHash(digest, signingCert.getPublicKey()))) {
                return signingCert;
            }
        } else {
            X500Name name = X500Name.getInstance(BCStrictStyle.INSTANCE, responderID.getName());
            if (responderCert != null && name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, responderCert.getSubjectX500Principal().getEncoded()))) {
                return responderCert;
            }

            if (signingCert != null && name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, signingCert.getSubjectX500Principal().getEncoded()))) {
                return signingCert;
            }
        }

        return null;
    }

    private static boolean responderMatches(ResponderID responderID, X509Certificate certificate, JcaJceHelper helper) throws NoSuchProviderException, NoSuchAlgorithmException {
        byte[] keyHash = responderID.getKeyHash();
        if (keyHash != null) {
            MessageDigest digest = helper.createMessageDigest("SHA1");
            return Arrays.areEqual(keyHash, calcKeyHash(digest, certificate.getPublicKey()));
        } else {
            X500Name name = X500Name.getInstance(BCStrictStyle.INSTANCE, responderID.getName());
            return name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, certificate.getSubjectX500Principal().getEncoded()));
        }
    }

    private static byte[] calcKeyHash(MessageDigest digest, PublicKey key) {
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(key.getEncoded());
        return digest.digest(info.getPublicKeyData().getBytes());
    }

    private com.mi.car.jsse.easysec.asn1.x509.Certificate extractCert() throws CertPathValidatorException {
        try {
            return com.mi.car.jsse.easysec.asn1.x509.Certificate.getInstance(this.parameters.getSigningCert().getEncoded());
        } catch (Exception var2) {
            throw new CertPathValidatorException("cannot process signing cert: " + var2.getMessage(), var2, this.parameters.getCertPath(), this.parameters.getIndex());
        }
    }

    private CertID createCertID(CertID base, com.mi.car.jsse.easysec.asn1.x509.Certificate issuer, ASN1Integer serialNumber) throws CertPathValidatorException {
        return this.createCertID(base.getHashAlgorithm(), issuer, serialNumber);
    }

    private CertID createCertID(AlgorithmIdentifier digestAlg, com.mi.car.jsse.easysec.asn1.x509.Certificate issuer, ASN1Integer serialNumber) throws CertPathValidatorException {
        try {
            MessageDigest digest = this.helper.createMessageDigest(MessageDigestUtils.getDigestName(digestAlg.getAlgorithm()));
            ASN1OctetString issuerNameHash = new DEROctetString(digest.digest(issuer.getSubject().getEncoded("DER")));
            ASN1OctetString issuerKeyHash = new DEROctetString(digest.digest(issuer.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));
            return new CertID(digestAlg, issuerNameHash, issuerKeyHash, serialNumber);
        } catch (Exception var7) {
            throw new CertPathValidatorException("problem creating ID: " + var7, var7);
        }
    }

    private static String getDigestName(ASN1ObjectIdentifier oid) {
        String name = MessageDigestUtils.getDigestName(oid);
        int dIndex = name.indexOf(45);
        return dIndex > 0 && !name.startsWith("SHA3") ? name.substring(0, dIndex) + name.substring(dIndex + 1) : name;
    }

    private static String getSignatureName(AlgorithmIdentifier sigAlgId) {
        ASN1Encodable params = sigAlgId.getParameters();
        if (params != null && !DERNull.INSTANCE.equals(params) && sigAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS)) {
            RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(params);
            return getDigestName(rsaParams.getHashAlgorithm().getAlgorithm()) + "WITHRSAANDMGF1";
        } else {
            return oids.containsKey(sigAlgId.getAlgorithm()) ? (String)oids.get(sigAlgId.getAlgorithm()) : sigAlgId.getAlgorithm().getId();
        }
    }

    static {
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "SHA1WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
        oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256WITHECGOST3410-2012-256");
        oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512WITHECGOST3410-2012-512");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");
        oids.put(IsaraObjectIdentifiers.id_alg_xmss, "XMSS");
        oids.put(IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "MD5WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "MD2WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "SHA1WITHDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
        oids.put(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
        oids.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");
    }
}
