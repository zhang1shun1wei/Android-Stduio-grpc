package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.Extension;
import com.mi.car.jsse.easysec.asn1.x509.TBSCertificate;
import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedBuilderParameters;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedParameters;
import com.mi.car.jsse.easysec.jcajce.interfaces.BCX509Certificate;
import com.mi.car.jsse.easysec.jcajce.util.BCJcaJceHelper;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jce.exception.ExtCertPathValidatorException;
import com.mi.car.jsse.easysec.x509.ExtendedPKIXParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.PolicyNode;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class PKIXCertPathValidatorSpi_8 extends CertPathValidatorSpi {
    private final JcaJceHelper helper;
    private final boolean isForCRLCheck;

    public PKIXCertPathValidatorSpi_8() {
        this(false);
    }

    public PKIXCertPathValidatorSpi_8(boolean isForCRLCheck) {
        this.helper = new BCJcaJceHelper();
        this.isForCRLCheck = isForCRLCheck;
    }

    public PKIXCertPathChecker engineGetRevocationChecker() {
        return new ProvRevocationChecker(this.helper);
    }

    public CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params) throws CertPathValidatorException, InvalidAlgorithmParameterException {
        PKIXExtendedParameters paramsPKIX;
        if (params instanceof PKIXParameters) {
            PKIXExtendedParameters.Builder paramsPKIXBldr = new PKIXExtendedParameters.Builder((PKIXParameters)params);
            if (params instanceof ExtendedPKIXParameters) {
                ExtendedPKIXParameters extPKIX = (ExtendedPKIXParameters)params;
                paramsPKIXBldr.setUseDeltasEnabled(extPKIX.isUseDeltasEnabled());
                paramsPKIXBldr.setValidityModel(extPKIX.getValidityModel());
            }

            paramsPKIX = paramsPKIXBldr.build();
        } else if (params instanceof PKIXExtendedBuilderParameters) {
            paramsPKIX = ((PKIXExtendedBuilderParameters)params).getBaseParameters();
        } else {
            if (!(params instanceof PKIXExtendedParameters)) {
                throw new InvalidAlgorithmParameterException("Parameters must be a " + PKIXParameters.class.getName() + " instance.");
            }

            paramsPKIX = (PKIXExtendedParameters)params;
        }

        if (paramsPKIX.getTrustAnchors() == null) {
            throw new InvalidAlgorithmParameterException("trustAnchors is null, this is not allowed for certification path validation.");
        } else {
            List certs = certPath.getCertificates();
            int n = certs.size();
            if (certs.isEmpty()) {
                throw new CertPathValidatorException("Certification path is empty.", (Throwable)null, certPath, -1);
            } else {
                Date currentDate = new Date();
                Date validityDate = CertPathValidatorUtilities.getValidityDate(paramsPKIX, currentDate);
                Set userInitialPolicySet = paramsPKIX.getInitialPolicies();

                TrustAnchor trust;
                try {
                    trust = CertPathValidatorUtilities.findTrustAnchor((X509Certificate)certs.get(certs.size() - 1), paramsPKIX.getTrustAnchors(), paramsPKIX.getSigProvider());
                    if (trust == null) {
                        throw new CertPathValidatorException("Trust anchor for certification path not found.", (Throwable)null, certPath, -1);
                    }

                    checkCertificate(trust.getTrustedCert());
                } catch (AnnotatedException var38) {
                    throw new CertPathValidatorException(var38.getMessage(), var38.getUnderlyingException(), certPath, certs.size() - 1);
                }

                paramsPKIX = (new PKIXExtendedParameters.Builder(paramsPKIX)).setTrustAnchor(trust).build();
                PKIXCertRevocationChecker revocationChecker = null;
                List pathCheckers = new ArrayList();
                Iterator certIter = paramsPKIX.getCertPathCheckers().iterator();

                while(certIter.hasNext()) {
                    PKIXCertPathChecker checker = (PKIXCertPathChecker)certIter.next();
                    checker.init(false);
                    if (checker instanceof PKIXRevocationChecker) {
                        if (revocationChecker != null) {
                            throw new CertPathValidatorException("only one PKIXRevocationChecker allowed");
                        }

                        revocationChecker = checker instanceof PKIXCertRevocationChecker ? (PKIXCertRevocationChecker)checker : new WrappedRevocationChecker(checker);
                    } else {
                        pathCheckers.add(checker);
                    }
                }

                if (paramsPKIX.isRevocationEnabled() && revocationChecker == null) {
                    revocationChecker = new ProvRevocationChecker(this.helper);
                }

                List[] policyNodes = new ArrayList[n + 1];

                for(int j = 0; j < policyNodes.length; ++j) {
                    policyNodes[j] = new ArrayList();
                }

                Set policySet = new HashSet();
                policySet.add("2.5.29.32.0");
                PKIXPolicyNode validPolicyTree = new PKIXPolicyNode(new ArrayList(), 0, policySet, (PolicyNode)null, new HashSet(), "2.5.29.32.0", false);
                policyNodes[0].add(validPolicyTree);
                PKIXNameConstraintValidator nameConstraintValidator = new PKIXNameConstraintValidator();
                Set acceptablePolicies = new HashSet();
                int explicitPolicy;
                if (paramsPKIX.isExplicitPolicyRequired()) {
                    explicitPolicy = 0;
                } else {
                    explicitPolicy = n + 1;
                }

                int inhibitAnyPolicy;
                if (paramsPKIX.isAnyPolicyInhibited()) {
                    inhibitAnyPolicy = 0;
                } else {
                    inhibitAnyPolicy = n + 1;
                }

                int policyMapping;
                if (paramsPKIX.isPolicyMappingInhibited()) {
                    policyMapping = 0;
                } else {
                    policyMapping = n + 1;
                }

                X509Certificate sign = trust.getTrustedCert();

                PublicKey workingPublicKey;
                X500Name workingIssuerName;
                try {
                    if (sign != null) {
                        workingIssuerName = PrincipalUtils.getSubjectPrincipal(sign);
                        workingPublicKey = sign.getPublicKey();
                    } else {
                        workingIssuerName = PrincipalUtils.getCA(trust);
                        workingPublicKey = trust.getCAPublicKey();
                    }
                } catch (RuntimeException var37) {
                    throw new ExtCertPathValidatorException("Subject of trust anchor could not be (re)encoded.", var37, certPath, -1);
                }

                AlgorithmIdentifier workingAlgId = null;

                try {
                    workingAlgId = CertPathValidatorUtilities.getAlgorithmIdentifier(workingPublicKey);
                } catch (CertPathValidatorException var36) {
                    throw new ExtCertPathValidatorException("Algorithm identifier of public key of trust anchor could not be read.", var36, certPath, -1);
                }

                ASN1ObjectIdentifier workingPublicKeyAlgorithm = workingAlgId.getAlgorithm();
                ASN1Encodable workingPublicKeyParameters = workingAlgId.getParameters();
                int maxPathLength = n;
                if (paramsPKIX.getTargetConstraints() != null && !paramsPKIX.getTargetConstraints().match((X509Certificate)certs.get(0))) {
                    throw new ExtCertPathValidatorException("Target certificate in certification path does not match targetConstraints.", (Throwable)null, certPath, 0);
                } else {
                    X509Certificate cert = null;

                    int index;
                    for(index = certs.size() - 1; index >= 0; --index) {
                        int i = n - index;
                        cert = (X509Certificate)certs.get(index);
                        boolean verificationAlreadyPerformed = index == certs.size() - 1;

                        try {
                            checkCertificate(cert);
                        } catch (AnnotatedException var34) {
                            throw new CertPathValidatorException(var34.getMessage(), var34.getUnderlyingException(), certPath, index);
                        }

                        RFC3280CertPathUtilities.processCertA(certPath, paramsPKIX, validityDate, (PKIXCertRevocationChecker)revocationChecker, index, workingPublicKey, verificationAlreadyPerformed, workingIssuerName, sign);
                        RFC3280CertPathUtilities.processCertBC(certPath, index, nameConstraintValidator, this.isForCRLCheck);
                        validPolicyTree = RFC3280CertPathUtilities.processCertD(certPath, index, acceptablePolicies, validPolicyTree, policyNodes, inhibitAnyPolicy, this.isForCRLCheck);
                        validPolicyTree = RFC3280CertPathUtilities.processCertE(certPath, index, validPolicyTree);
                        RFC3280CertPathUtilities.processCertF(certPath, index, validPolicyTree, explicitPolicy);
                        if (i != n) {
                            if (cert != null && cert.getVersion() == 1) {
                                if (i != 1 || !cert.equals(trust.getTrustedCert())) {
                                    throw new CertPathValidatorException("Version 1 certificates can't be used as CA ones.", (Throwable)null, certPath, index);
                                }
                            } else {
                                RFC3280CertPathUtilities.prepareNextCertA(certPath, index);
                                validPolicyTree = RFC3280CertPathUtilities.prepareCertB(certPath, index, policyNodes, validPolicyTree, policyMapping);
                                RFC3280CertPathUtilities.prepareNextCertG(certPath, index, nameConstraintValidator);
                                explicitPolicy = RFC3280CertPathUtilities.prepareNextCertH1(certPath, index, explicitPolicy);
                                policyMapping = RFC3280CertPathUtilities.prepareNextCertH2(certPath, index, policyMapping);
                                inhibitAnyPolicy = RFC3280CertPathUtilities.prepareNextCertH3(certPath, index, inhibitAnyPolicy);
                                explicitPolicy = RFC3280CertPathUtilities.prepareNextCertI1(certPath, index, explicitPolicy);
                                policyMapping = RFC3280CertPathUtilities.prepareNextCertI2(certPath, index, policyMapping);
                                inhibitAnyPolicy = RFC3280CertPathUtilities.prepareNextCertJ(certPath, index, inhibitAnyPolicy);
                                RFC3280CertPathUtilities.prepareNextCertK(certPath, index);
                                maxPathLength = RFC3280CertPathUtilities.prepareNextCertL(certPath, index, maxPathLength);
                                maxPathLength = RFC3280CertPathUtilities.prepareNextCertM(certPath, index, maxPathLength);
                                RFC3280CertPathUtilities.prepareNextCertN(certPath, index);
                                Set criticalExtensions = cert.getCriticalExtensionOIDs();
                                if (criticalExtensions != null) {
                                    criticalExtensions = new HashSet(criticalExtensions);
                                    criticalExtensions.remove(RFC3280CertPathUtilities.KEY_USAGE);
                                    criticalExtensions.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
                                    criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
                                    criticalExtensions.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
                                    criticalExtensions.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
                                    criticalExtensions.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
                                    criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
                                    criticalExtensions.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
                                    criticalExtensions.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
                                    criticalExtensions.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
                                } else {
                                    criticalExtensions = new HashSet();
                                }

                                RFC3280CertPathUtilities.prepareNextCertO(certPath, index, criticalExtensions, pathCheckers);
                                sign = cert;
                                workingIssuerName = PrincipalUtils.getSubjectPrincipal(cert);

                                try {
                                    workingPublicKey = CertPathValidatorUtilities.getNextWorkingKey(certPath.getCertificates(), index, this.helper);
                                } catch (CertPathValidatorException var35) {
                                    throw new CertPathValidatorException("Next working key could not be retrieved.", var35, certPath, index);
                                }

                                workingAlgId = CertPathValidatorUtilities.getAlgorithmIdentifier(workingPublicKey);
                                workingPublicKeyAlgorithm = workingAlgId.getAlgorithm();
                                workingPublicKeyParameters = workingAlgId.getParameters();
                            }
                        }
                    }

                    explicitPolicy = RFC3280CertPathUtilities.wrapupCertA(explicitPolicy, cert);
                    explicitPolicy = RFC3280CertPathUtilities.wrapupCertB(certPath, index + 1, explicitPolicy);
                    Set criticalExtensions = cert.getCriticalExtensionOIDs();
                    if (criticalExtensions != null) {
                        criticalExtensions = new HashSet(criticalExtensions);
                        criticalExtensions.remove(RFC3280CertPathUtilities.KEY_USAGE);
                        criticalExtensions.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
                        criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
                        criticalExtensions.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
                        criticalExtensions.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
                        criticalExtensions.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
                        criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
                        criticalExtensions.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
                        criticalExtensions.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
                        criticalExtensions.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
                        criticalExtensions.remove(RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS);
                        criticalExtensions.remove(Extension.extendedKeyUsage.getId());
                    } else {
                        criticalExtensions = new HashSet();
                    }

                    RFC3280CertPathUtilities.wrapupCertF(certPath, index + 1, pathCheckers, criticalExtensions);
                    PKIXPolicyNode intersection = RFC3280CertPathUtilities.wrapupCertG(certPath, paramsPKIX, userInitialPolicySet, index + 1, policyNodes, validPolicyTree, acceptablePolicies);
                    if (explicitPolicy <= 0 && intersection == null) {
                        throw new CertPathValidatorException("Path processing failed on policy.", (Throwable)null, certPath, index);
                    } else {
                        return new PKIXCertPathValidatorResult(trust, intersection, cert.getPublicKey());
                    }
                }
            }
        }
    }

    static void checkCertificate(X509Certificate cert) throws AnnotatedException {
        if (cert instanceof BCX509Certificate) {
            RuntimeException cause = null;

            try {
                if (null != ((BCX509Certificate)cert).getTBSCertificateNative()) {
                    return;
                }
            } catch (RuntimeException var3) {
                cause = var3;
            }

            throw new AnnotatedException("unable to process TBSCertificate", cause);
        } else {
            try {
                TBSCertificate.getInstance(cert.getTBSCertificate());
            } catch (CertificateEncodingException var4) {
                throw new AnnotatedException("unable to process TBSCertificate", var4);
            } catch (IllegalArgumentException var5) {
                throw new AnnotatedException(var5.getMessage());
            }
        }
    }
}
