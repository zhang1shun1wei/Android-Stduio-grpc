package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Enumerated;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1OutputStream;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1String;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x500.style.RFC4519Style;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.AuthorityKeyIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.CRLDistPoint;
import com.mi.car.jsse.easysec.asn1.x509.DistributionPoint;
import com.mi.car.jsse.easysec.asn1.x509.DistributionPointName;
import com.mi.car.jsse.easysec.asn1.x509.Extension;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import com.mi.car.jsse.easysec.asn1.x509.GeneralNames;
import com.mi.car.jsse.easysec.asn1.x509.PolicyInformation;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.internal.asn1.isismtt.ISISMTTObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.PKIXCRLStore;
import com.mi.car.jsse.easysec.jcajce.PKIXCRLStoreSelector;
import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationCheckerParameters;
import com.mi.car.jsse.easysec.jcajce.PKIXCertStore;
import com.mi.car.jsse.easysec.jcajce.PKIXCertStoreSelector;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedBuilderParameters;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedParameters;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jce.exception.ExtCertPathBuilderException;
import com.mi.car.jsse.easysec.jce.exception.ExtCertPathValidatorException;
import com.mi.car.jsse.easysec.util.Properties;
import com.mi.car.jsse.easysec.util.Store;
import com.mi.car.jsse.easysec.util.StoreException;
import com.mi.car.jsse.easysec.x509.X509AttributeCertificate;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PolicyQualifierInfo;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;


class CertPathValidatorUtilities {
    protected static final String CERTIFICATE_POLICIES;
    protected static final String BASIC_CONSTRAINTS;
    protected static final String POLICY_MAPPINGS;
    protected static final String SUBJECT_ALTERNATIVE_NAME;
    protected static final String NAME_CONSTRAINTS;
    protected static final String KEY_USAGE;
    protected static final String INHIBIT_ANY_POLICY;
    protected static final String ISSUING_DISTRIBUTION_POINT;
    protected static final String DELTA_CRL_INDICATOR;
    protected static final String POLICY_CONSTRAINTS;
    protected static final String FRESHEST_CRL;
    protected static final String CRL_DISTRIBUTION_POINTS;
    protected static final String AUTHORITY_KEY_IDENTIFIER;
    protected static final String ANY_POLICY = "2.5.29.32.0";
    protected static final String CRL_NUMBER;
    protected static final int KEY_CERT_SIGN = 5;
    protected static final int CRL_SIGN = 6;
    protected static final String[] crlReasons;

    CertPathValidatorUtilities() {
    }

    static Collection findTargets(PKIXExtendedBuilderParameters paramsPKIX) throws CertPathBuilderException {
        PKIXExtendedParameters baseParams = paramsPKIX.getBaseParameters();
        PKIXCertStoreSelector certSelect = baseParams.getTargetConstraints();
        LinkedHashSet targets = new LinkedHashSet();

        try {
            findCertificates(targets, certSelect, baseParams.getCertificateStores());
            findCertificates(targets, certSelect, baseParams.getCertStores());
        } catch (AnnotatedException var5) {
            throw new ExtCertPathBuilderException("Error finding target certificate.", var5);
        }

        if (!targets.isEmpty()) {
            return targets;
        } else {
            Certificate target = certSelect.getCertificate();
            if (null == target) {
                throw new CertPathBuilderException("No certificate found matching targetConstraints.");
            } else {
                return Collections.singleton(target);
            }
        }
    }

    protected static TrustAnchor findTrustAnchor(X509Certificate cert, Set trustAnchors) throws AnnotatedException {
        return findTrustAnchor(cert, trustAnchors, (String)null);
    }

    protected static TrustAnchor findTrustAnchor(X509Certificate cert, Set trustAnchors, String sigProvider) throws AnnotatedException {
        TrustAnchor trust = null;
        PublicKey trustPublicKey = null;
        Exception invalidKeyEx = null;
        X509CertSelector certSelectX509 = new X509CertSelector();
        X500Principal certIssuerPrincipal = cert.getIssuerX500Principal();
        certSelectX509.setSubject(certIssuerPrincipal);
        X500Name certIssuerName = null;
        Iterator iter = trustAnchors.iterator();

        while(iter.hasNext() && trust == null) {
            trust = (TrustAnchor)iter.next();
            if (trust.getTrustedCert() != null) {
                if (certSelectX509.match(trust.getTrustedCert())) {
                    trustPublicKey = trust.getTrustedCert().getPublicKey();
                } else {
                    trust = null;
                }
            } else if (trust.getCA() != null && trust.getCAName() != null && trust.getCAPublicKey() != null) {
                if (certIssuerName == null) {
                    certIssuerName = X500Name.getInstance(certIssuerPrincipal.getEncoded());
                }

                try {
                    X500Name caName = X500Name.getInstance(trust.getCA().getEncoded());
                    if (certIssuerName.equals(caName)) {
                        trustPublicKey = trust.getCAPublicKey();
                    } else {
                        trust = null;
                    }
                } catch (IllegalArgumentException var12) {
                    trust = null;
                }
            } else {
                trust = null;
            }

            if (trustPublicKey != null) {
                try {
                    verifyX509Certificate(cert, trustPublicKey, sigProvider);
                } catch (Exception var11) {
                    invalidKeyEx = var11;
                    trust = null;
                    trustPublicKey = null;
                }
            }
        }

        if (trust == null && invalidKeyEx != null) {
            throw new AnnotatedException("TrustAnchor found but certificate validation failed.", invalidKeyEx);
        } else {
            return trust;
        }
    }

    static boolean isIssuerTrustAnchor(X509Certificate cert, Set trustAnchors, String sigProvider) throws AnnotatedException {
        try {
            return findTrustAnchor(cert, trustAnchors, sigProvider) != null;
        } catch (Exception var4) {
            return false;
        }
    }

    static List<PKIXCertStore> getAdditionalStoresFromAltNames(byte[] issuerAlternativeName, Map<GeneralName, PKIXCertStore> altNameCertStoreMap) throws CertificateParsingException {
        if (issuerAlternativeName == null) {
            return Collections.EMPTY_LIST;
        } else {
            GeneralNames issuerAltName = GeneralNames.getInstance(ASN1OctetString.getInstance(issuerAlternativeName).getOctets());
            GeneralName[] names = issuerAltName.getNames();
            List<PKIXCertStore> stores = new ArrayList();

            for(int i = 0; i != names.length; ++i) {
                GeneralName altName = names[i];
                PKIXCertStore altStore = (PKIXCertStore)altNameCertStoreMap.get(altName);
                if (altStore != null) {
                    stores.add(altStore);
                }
            }

            return stores;
        }
    }

    protected static Date getValidityDate(PKIXExtendedParameters paramsPKIX, Date currentDate) {
        Date validityDate = paramsPKIX.getValidityDate();
        return null == validityDate ? currentDate : validityDate;
    }

    protected static boolean isSelfIssued(X509Certificate cert) {
        return cert.getSubjectDN().equals(cert.getIssuerDN());
    }

    protected static ASN1Primitive getExtensionValue(X509Extension ext, String oid) throws AnnotatedException {
        byte[] bytes = ext.getExtensionValue(oid);
        return null == bytes ? null : getObject(oid, bytes);
    }

    private static ASN1Primitive getObject(String oid, byte[] ext) throws AnnotatedException {
        try {
            ASN1OctetString octs = ASN1OctetString.getInstance(ext);
            return ASN1Primitive.fromByteArray(octs.getOctets());
        } catch (Exception var3) {
            throw new AnnotatedException("exception processing extension " + oid, var3);
        }
    }

    protected static AlgorithmIdentifier getAlgorithmIdentifier(PublicKey key) throws CertPathValidatorException {
        try {
            return SubjectPublicKeyInfo.getInstance(key.getEncoded()).getAlgorithm();
        } catch (Exception var2) {
            throw new ExtCertPathValidatorException("Subject public key cannot be decoded.", var2);
        }
    }

    protected static final Set getQualifierSet(ASN1Sequence qualifiers) throws CertPathValidatorException {
        Set pq = new HashSet();
        if (qualifiers == null) {
            return pq;
        } else {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream aOut = ASN1OutputStream.create(bOut);

            for(Enumeration e = qualifiers.getObjects(); e.hasMoreElements(); bOut.reset()) {
                try {
                    aOut.writeObject((ASN1Encodable)e.nextElement());
                    pq.add(new PolicyQualifierInfo(bOut.toByteArray()));
                } catch (IOException var6) {
                    throw new ExtCertPathValidatorException("Policy qualifier info cannot be decoded.", var6);
                }
            }

            return pq;
        }
    }

    protected static PKIXPolicyNode removePolicyNode(PKIXPolicyNode validPolicyTree, List[] policyNodes, PKIXPolicyNode _node) {
        PKIXPolicyNode _parent = (PKIXPolicyNode)_node.getParent();
        if (validPolicyTree == null) {
            return null;
        } else if (_parent != null) {
            _parent.removeChild(_node);
            removePolicyNodeRecurse(policyNodes, _node);
            return validPolicyTree;
        } else {
            for(int j = 0; j < policyNodes.length; ++j) {
                policyNodes[j] = new ArrayList();
            }

            return null;
        }
    }

    private static void removePolicyNodeRecurse(List[] policyNodes, PKIXPolicyNode _node) {
        policyNodes[_node.getDepth()].remove(_node);
        if (_node.hasChildren()) {
            Iterator _iter = _node.getChildren();

            while(_iter.hasNext()) {
                PKIXPolicyNode _child = (PKIXPolicyNode)_iter.next();
                removePolicyNodeRecurse(policyNodes, _child);
            }
        }

    }

    protected static boolean processCertD1i(int index, List[] policyNodes, ASN1ObjectIdentifier pOid, Set pq) {
        List policyNodeVec = policyNodes[index - 1];

        for(int j = 0; j < policyNodeVec.size(); ++j) {
            PKIXPolicyNode node = (PKIXPolicyNode)policyNodeVec.get(j);
            Set expectedPolicies = node.getExpectedPolicies();
            if (expectedPolicies.contains(pOid.getId())) {
                Set childExpectedPolicies = new HashSet();
                childExpectedPolicies.add(pOid.getId());
                PKIXPolicyNode child = new PKIXPolicyNode(new ArrayList(), index, childExpectedPolicies, node, pq, pOid.getId(), false);
                node.addChild(child);
                policyNodes[index].add(child);
                return true;
            }
        }

        return false;
    }

    protected static void processCertD1ii(int index, List[] policyNodes, ASN1ObjectIdentifier _poid, Set _pq) {
        List policyNodeVec = policyNodes[index - 1];

        for(int j = 0; j < policyNodeVec.size(); ++j) {
            PKIXPolicyNode _node = (PKIXPolicyNode)policyNodeVec.get(j);
            if ("2.5.29.32.0".equals(_node.getValidPolicy())) {
                Set _childExpectedPolicies = new HashSet();
                _childExpectedPolicies.add(_poid.getId());
                PKIXPolicyNode _child = new PKIXPolicyNode(new ArrayList(), index, _childExpectedPolicies, _node, _pq, _poid.getId(), false);
                _node.addChild(_child);
                policyNodes[index].add(_child);
                return;
            }
        }

    }

    protected static void prepareNextCertB1(int i, List[] policyNodes, String id_p, Map m_idp, X509Certificate cert) throws AnnotatedException, CertPathValidatorException {
        boolean idp_found = false;
        Iterator nodes_i = policyNodes[i].iterator();

        PKIXPolicyNode node;
        while(nodes_i.hasNext()) {
            node = (PKIXPolicyNode)nodes_i.next();
            if (node.getValidPolicy().equals(id_p)) {
                idp_found = true;
                node.expectedPolicies = (Set)m_idp.get(id_p);
                break;
            }
        }

        if (!idp_found) {
            nodes_i = policyNodes[i].iterator();

            while(nodes_i.hasNext()) {
                node = (PKIXPolicyNode)nodes_i.next();
                if ("2.5.29.32.0".equals(node.getValidPolicy())) {
                    Set pq = null;
                    ASN1Sequence policies = null;

                    try {
                        policies = DERSequence.getInstance(getExtensionValue(cert, CERTIFICATE_POLICIES));
                    } catch (Exception var16) {
                        throw new AnnotatedException("Certificate policies cannot be decoded.", var16);
                    }

                    Enumeration e = policies.getObjects();

                    while(e.hasMoreElements()) {
                        PolicyInformation pinfo = null;

                        try {
                            pinfo = PolicyInformation.getInstance(e.nextElement());
                        } catch (Exception var15) {
                            throw new AnnotatedException("Policy information cannot be decoded.", var15);
                        }

                        if ("2.5.29.32.0".equals(pinfo.getPolicyIdentifier().getId())) {
                            try {
                                pq = getQualifierSet(pinfo.getPolicyQualifiers());
                                break;
                            } catch (CertPathValidatorException var14) {
                                throw new ExtCertPathValidatorException("Policy qualifier info set could not be built.", var14);
                            }
                        }
                    }

                    boolean ci = false;
                    if (cert.getCriticalExtensionOIDs() != null) {
                        ci = cert.getCriticalExtensionOIDs().contains(CERTIFICATE_POLICIES);
                    }

                    PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
                    if ("2.5.29.32.0".equals(p_node.getValidPolicy())) {
                        PKIXPolicyNode c_node = new PKIXPolicyNode(new ArrayList(), i, (Set)m_idp.get(id_p), p_node, pq, id_p, ci);
                        p_node.addChild(c_node);
                        policyNodes[i].add(c_node);
                    }
                    break;
                }
            }
        }

    }

    protected static PKIXPolicyNode prepareNextCertB2(int i, List[] policyNodes, String id_p, PKIXPolicyNode validPolicyTree) {
        Iterator nodes_i = policyNodes[i].iterator();

        while(true) {
            PKIXPolicyNode node;
            do {
                if (!nodes_i.hasNext()) {
                    return validPolicyTree;
                }

                node = (PKIXPolicyNode)nodes_i.next();
            } while(!node.getValidPolicy().equals(id_p));

            PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
            p_node.removeChild(node);
            nodes_i.remove();

            for(int k = i - 1; k >= 0; --k) {
                List nodes = policyNodes[k];

                for(int l = 0; l < nodes.size(); ++l) {
                    PKIXPolicyNode node2 = (PKIXPolicyNode)nodes.get(l);
                    if (!node2.hasChildren()) {
                        validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, node2);
                        if (validPolicyTree == null) {
                            break;
                        }
                    }
                }
            }
        }
    }

    protected static boolean isAnyPolicy(Set policySet) {
        return policySet == null || policySet.contains("2.5.29.32.0") || policySet.isEmpty();
    }

    protected static void findCertificates(LinkedHashSet certs, PKIXCertStoreSelector certSelect, List certStores) throws AnnotatedException {
        Iterator iter = certStores.iterator();

        while(iter.hasNext()) {
            Object obj = iter.next();
            if (obj instanceof Store) {
                Store certStore = (Store)obj;

                try {
                    certs.addAll(certStore.getMatches(certSelect));
                } catch (StoreException var7) {
                    throw new AnnotatedException("Problem while picking certificates from X.509 store.", var7);
                }
            } else {
                CertStore certStore = (CertStore)obj;

                try {
                    certs.addAll(PKIXCertStoreSelector.getCertificates(certSelect, certStore));
                } catch (CertStoreException var8) {
                    throw new AnnotatedException("Problem while picking certificates from certificate store.", var8);
                }
            }
        }

    }

    static List<PKIXCRLStore> getAdditionalStoresFromCRLDistributionPoint(CRLDistPoint crldp, Map<GeneralName, PKIXCRLStore> namedCRLStoreMap, Date validDate, JcaJceHelper helper) throws AnnotatedException {
        if (null == crldp) {
            return Collections.EMPTY_LIST;
        } else {
            DistributionPoint[] dps;
            try {
                dps = crldp.getDistributionPoints();
            } catch (Exception var15) {
                throw new AnnotatedException("Distribution points could not be read.", var15);
            }

            List<PKIXCRLStore> stores = new ArrayList();

            for(int i = 0; i < dps.length; ++i) {
                DistributionPointName dpn = dps[i].getDistributionPoint();
                if (dpn != null && dpn.getType() == 0) {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();

                    for(int j = 0; j < genNames.length; ++j) {
                        PKIXCRLStore store = (PKIXCRLStore)namedCRLStoreMap.get(genNames[j]);
                        if (store != null) {
                            stores.add(store);
                        }
                    }
                }
            }

            if (stores.isEmpty() && Properties.isOverrideSet("com.mi.car.jsse.easysec.x509.enableCRLDP")) {
                CertificateFactory certFact;
                try {
                    certFact = helper.createCertificateFactory("X.509");
                } catch (Exception var14) {
                    throw new AnnotatedException("cannot create certificate factory: " + var14.getMessage(), var14);
                }

                for(int i = 0; i < dps.length; ++i) {
                    DistributionPointName dpn = dps[i].getDistributionPoint();
                    if (dpn != null && dpn.getType() == 0) {
                        GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();

                        for(int j = 0; j < genNames.length; ++j) {
                            GeneralName name = genNames[i];
                            if (name.getTagNo() == 6) {
                                try {
                                    URI distributionPoint = new URI(((ASN1String)name.getName()).getString());
                                    PKIXCRLStore store = CrlCache.getCrl(certFact, validDate, distributionPoint);
                                    if (store != null) {
                                        stores.add(store);
                                    }
                                    break;
                                } catch (Exception var16) {
                                }
                            }
                        }
                    }
                }
            }

            return stores;
        }
    }

    protected static void getCRLIssuersFromDistributionPoint(DistributionPoint dp, Collection issuerPrincipals, X509CRLSelector selector) throws AnnotatedException {
        List issuers = new ArrayList();
        Iterator it;
        if (dp.getCRLIssuer() != null) {
            GeneralName[] genNames = dp.getCRLIssuer().getNames();

            for(int j = 0; j < genNames.length; ++j) {
                if (genNames[j].getTagNo() == 4) {
                    try {
                        issuers.add(X500Name.getInstance(genNames[j].getName().toASN1Primitive().getEncoded()));
                    } catch (IOException var8) {
                        throw new AnnotatedException("CRL issuer information from distribution point cannot be decoded.", var8);
                    }
                }
            }
        } else {
            if (dp.getDistributionPoint() == null) {
                throw new AnnotatedException("CRL issuer is omitted from distribution point but no distributionPoint field present.");
            }

            it = issuerPrincipals.iterator();

            while(it.hasNext()) {
                issuers.add(it.next());
            }
        }

        it = issuers.iterator();

        while(it.hasNext()) {
            try {
                selector.addIssuerName(((X500Name)it.next()).getEncoded());
            } catch (IOException var7) {
                throw new AnnotatedException("Cannot decode CRL issuer information.", var7);
            }
        }

    }

    private static BigInteger getSerialNumber(Object cert) {
        return ((X509Certificate)cert).getSerialNumber();
    }

    protected static void getCertStatus(Date validDate, X509CRL crl, Object cert, CertStatus certStatus) throws AnnotatedException {
        boolean isIndirect;
        try {
            isIndirect = X509CRLObject.isIndirectCRL(crl);
        } catch (CRLException var9) {
            throw new AnnotatedException("Failed check for indirect CRL.", var9);
        }

        X509CRLEntry crl_entry;
        if (isIndirect) {
            crl_entry = crl.getRevokedCertificate(getSerialNumber(cert));
            if (crl_entry == null) {
                return;
            }

            X500Principal certificateIssuer = crl_entry.getCertificateIssuer();
            X500Name certIssuer;
            if (certificateIssuer == null) {
                certIssuer = PrincipalUtils.getIssuerPrincipal(crl);
            } else {
                certIssuer = PrincipalUtils.getX500Name(certificateIssuer);
            }

            if (!PrincipalUtils.getEncodedIssuerPrincipal(cert).equals(certIssuer)) {
                return;
            }
        } else {
            if (!PrincipalUtils.getEncodedIssuerPrincipal(cert).equals(PrincipalUtils.getIssuerPrincipal(crl))) {
                return;
            }

            crl_entry = crl.getRevokedCertificate(getSerialNumber(cert));
            if (crl_entry == null) {
                return;
            }
        }

        ASN1Enumerated reasonCode = null;
        if (crl_entry.hasExtensions()) {
            if (crl_entry.hasUnsupportedCriticalExtension()) {
                throw new AnnotatedException("CRL entry has unsupported critical extensions.");
            }

            try {
                reasonCode = ASN1Enumerated.getInstance(getExtensionValue(crl_entry, Extension.reasonCode.getId()));
            } catch (Exception var8) {
                throw new AnnotatedException("Reason code CRL entry extension could not be decoded.", var8);
            }
        }

        int reasonCodeValue = null == reasonCode ? 0 : reasonCode.intValueExact();
        if (validDate.getTime() >= crl_entry.getRevocationDate().getTime() || reasonCodeValue == 0 || reasonCodeValue == 1 || reasonCodeValue == 2 || reasonCodeValue == 10) {
            certStatus.setCertStatus(reasonCodeValue);
            certStatus.setRevocationDate(crl_entry.getRevocationDate());
        }

    }

    protected static Set getDeltaCRLs(Date validityDate, X509CRL completeCRL, List<CertStore> certStores, List<PKIXCRLStore> pkixCrlStores, JcaJceHelper helper) throws AnnotatedException {
        X509CRLSelector baseDeltaSelect = new X509CRLSelector();

        try {
            baseDeltaSelect.addIssuerName(PrincipalUtils.getIssuerPrincipal(completeCRL).getEncoded());
        } catch (IOException var22) {
            throw new AnnotatedException("Cannot extract issuer from CRL.", var22);
        }

        BigInteger completeCRLNumber = null;

        try {
            ASN1Primitive derObject = getExtensionValue(completeCRL, CRL_NUMBER);
            if (derObject != null) {
                completeCRLNumber = ASN1Integer.getInstance(derObject).getPositiveValue();
            }
        } catch (Exception var24) {
            throw new AnnotatedException("CRL number extension could not be extracted from CRL.", var24);
        }

        byte[] idp;
        try {
            idp = completeCRL.getExtensionValue(ISSUING_DISTRIBUTION_POINT);
        } catch (Exception var21) {
            throw new AnnotatedException("Issuing distribution point extension value could not be read.", var21);
        }

        baseDeltaSelect.setMinCRLNumber(completeCRLNumber == null ? null : completeCRLNumber.add(BigInteger.valueOf(1L)));
        PKIXCRLStoreSelector.Builder selBuilder = new PKIXCRLStoreSelector.Builder(baseDeltaSelect);
        selBuilder.setIssuingDistributionPoint(idp);
        selBuilder.setIssuingDistributionPointEnabled(true);
        selBuilder.setMaxBaseCRLNumber(completeCRLNumber);
        PKIXCRLStoreSelector deltaSelect = selBuilder.build();
        Set temp = PKIXCRLUtil.findCRLs(deltaSelect, validityDate, certStores, pkixCrlStores);
        if (temp.isEmpty() && Properties.isOverrideSet("com.mi.car.jsse.easysec.x509.enableCRLDP")) {
            CertificateFactory certFact;
            try {
                certFact = helper.createCertificateFactory("X.509");
            } catch (Exception var20) {
                throw new AnnotatedException("cannot create certificate factory: " + var20.getMessage(), var20);
            }

            CRLDistPoint id = CRLDistPoint.getInstance(idp);
            DistributionPoint[] dps = id.getDistributionPoints();

            for(int i = 0; i < dps.length; ++i) {
                DistributionPointName dpn = dps[i].getDistributionPoint();
                if (dpn != null && dpn.getType() == 0) {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();

                    for(int j = 0; j < genNames.length; ++j) {
                        GeneralName name = genNames[i];
                        if (name.getTagNo() == 6) {
                            try {
                                PKIXCRLStore store = CrlCache.getCrl(certFact, validityDate, new URI(((ASN1String)name.getName()).getString()));
                                if (store != null) {
                                    temp = PKIXCRLUtil.findCRLs(deltaSelect, validityDate, Collections.EMPTY_LIST, Collections.singletonList(store));
                                }
                                break;
                            } catch (Exception var23) {
                            }
                        }
                    }
                }
            }
        }

        Set result = new HashSet();
        Iterator it = temp.iterator();

        while(it.hasNext()) {
            X509CRL crl = (X509CRL)it.next();
            if (isDeltaCRL(crl)) {
                result.add(crl);
            }
        }

        return result;
    }

    private static boolean isDeltaCRL(X509CRL crl) {
        Set critical = crl.getCriticalExtensionOIDs();
        return critical == null ? false : critical.contains(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
    }

    protected static Set getCompleteCRLs(PKIXCertRevocationCheckerParameters params, DistributionPoint dp, Object cert, PKIXExtendedParameters paramsPKIX, Date validityDate) throws AnnotatedException, RecoverableCertPathValidatorException {
        X509CRLSelector baseCrlSelect = new X509CRLSelector();

        try {
            Set issuers = new HashSet();
            issuers.add(PrincipalUtils.getEncodedIssuerPrincipal(cert));
            getCRLIssuersFromDistributionPoint(dp, issuers, baseCrlSelect);
        } catch (AnnotatedException var8) {
            throw new AnnotatedException("Could not get issuer information from distribution point.", var8);
        }

        if (cert instanceof X509Certificate) {
            baseCrlSelect.setCertificateChecking((X509Certificate)cert);
        }

        PKIXCRLStoreSelector crlSelect = (new PKIXCRLStoreSelector.Builder(baseCrlSelect)).setCompleteCRLEnabled(true).build();
        Set crls = PKIXCRLUtil.findCRLs(crlSelect, validityDate, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());
        checkCRLsNotEmpty(params, crls, cert);
        return crls;
    }

    protected static Date getValidCertDateFromValidityModel(Date validityDate, int validityModel, CertPath certPath, int index) throws AnnotatedException {
        if (1 == validityModel && index > 0) {
            X509Certificate issuedCert = (X509Certificate)certPath.getCertificates().get(index - 1);
            if (index - 1 == 0) {
                ASN1GeneralizedTime dateOfCertgen = null;

                try {
                    byte[] extBytes = ((X509Certificate)certPath.getCertificates().get(index - 1)).getExtensionValue(ISISMTTObjectIdentifiers.id_isismtt_at_dateOfCertGen.getId());
                    if (extBytes != null) {
                        dateOfCertgen = ASN1GeneralizedTime.getInstance(ASN1Primitive.fromByteArray(extBytes));
                    }
                } catch (IOException var8) {
                    throw new AnnotatedException("Date of cert gen extension could not be read.");
                } catch (IllegalArgumentException var9) {
                    throw new AnnotatedException("Date of cert gen extension could not be read.");
                }

                if (dateOfCertgen != null) {
                    try {
                        return dateOfCertgen.getDate();
                    } catch (ParseException var7) {
                        throw new AnnotatedException("Date from date of cert gen extension could not be parsed.", var7);
                    }
                }
            }

            return issuedCert.getNotBefore();
        } else {
            return validityDate;
        }
    }

    protected static PublicKey getNextWorkingKey(List certs, int index, JcaJceHelper helper) throws CertPathValidatorException {
        Certificate cert = (Certificate)certs.get(index);
        PublicKey pubKey = cert.getPublicKey();
        if (!(pubKey instanceof DSAPublicKey)) {
            return pubKey;
        } else {
            DSAPublicKey dsaPubKey = (DSAPublicKey)pubKey;
            if (dsaPubKey.getParams() != null) {
                return dsaPubKey;
            } else {
                for(int i = index + 1; i < certs.size(); ++i) {
                    X509Certificate parentCert = (X509Certificate)certs.get(i);
                    pubKey = parentCert.getPublicKey();
                    if (!(pubKey instanceof DSAPublicKey)) {
                        throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
                    }

                    DSAPublicKey prevDSAPubKey = (DSAPublicKey)pubKey;
                    if (prevDSAPubKey.getParams() != null) {
                        DSAParams dsaParams = prevDSAPubKey.getParams();
                        DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(dsaPubKey.getY(), dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

                        try {
                            KeyFactory keyFactory = helper.createKeyFactory("DSA");
                            return keyFactory.generatePublic(dsaPubKeySpec);
                        } catch (Exception var12) {
                            throw new RuntimeException(var12.getMessage());
                        }
                    }
                }

                throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
            }
        }
    }

    static Collection findIssuerCerts(X509Certificate cert, List<CertStore> certStores, List<PKIXCertStore> pkixCertStores) throws AnnotatedException {
        X509CertSelector selector = new X509CertSelector();

        try {
            selector.setSubject(PrincipalUtils.getIssuerPrincipal(cert).getEncoded());
        } catch (Exception var9) {
            throw new AnnotatedException("Subject criteria for certificate selector to find issuer certificate could not be set.", var9);
        }

        try {
            byte[] akiExtensionValue = cert.getExtensionValue(AUTHORITY_KEY_IDENTIFIER);
            if (akiExtensionValue != null) {
                ASN1OctetString aki = ASN1OctetString.getInstance(akiExtensionValue);
                byte[] authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(aki.getOctets()).getKeyIdentifier();
                if (authorityKeyIdentifier != null) {
                    selector.setSubjectKeyIdentifier((new DEROctetString(authorityKeyIdentifier)).getEncoded());
                }
            }
        } catch (Exception var8) {
        }

        PKIXCertStoreSelector certSelect = (new PKIXCertStoreSelector.Builder(selector)).build();
        LinkedHashSet certs = new LinkedHashSet();

        try {
            findCertificates(certs, certSelect, certStores);
            findCertificates(certs, certSelect, pkixCertStores);
            return certs;
        } catch (AnnotatedException var7) {
            throw new AnnotatedException("Issuer certificate cannot be searched.", var7);
        }
    }

    protected static void verifyX509Certificate(X509Certificate cert, PublicKey publicKey, String sigProvider) throws GeneralSecurityException {
        if (sigProvider == null) {
            cert.verify(publicKey);
        } else {
            cert.verify(publicKey, sigProvider);
        }

    }

    static void checkCRLsNotEmpty(PKIXCertRevocationCheckerParameters params, Set crls, Object cert) throws RecoverableCertPathValidatorException {
        if (crls.isEmpty()) {
            if (cert instanceof X509AttributeCertificate) {
                X509AttributeCertificate aCert = (X509AttributeCertificate)cert;
                throw new RecoverableCertPathValidatorException("No CRLs found for issuer \"" + aCert.getIssuer().getPrincipals()[0] + "\"", (Throwable)null, params.getCertPath(), params.getIndex());
            } else {
                X509Certificate xCert = (X509Certificate)cert;
                throw new RecoverableCertPathValidatorException("No CRLs found for issuer \"" + RFC4519Style.INSTANCE.toString(PrincipalUtils.getIssuerPrincipal(xCert)) + "\"", (Throwable)null, params.getCertPath(), params.getIndex());
            }
        }
    }

    static {
        CERTIFICATE_POLICIES = Extension.certificatePolicies.getId();
        BASIC_CONSTRAINTS = Extension.basicConstraints.getId();
        POLICY_MAPPINGS = Extension.policyMappings.getId();
        SUBJECT_ALTERNATIVE_NAME = Extension.subjectAlternativeName.getId();
        NAME_CONSTRAINTS = Extension.nameConstraints.getId();
        KEY_USAGE = Extension.keyUsage.getId();
        INHIBIT_ANY_POLICY = Extension.inhibitAnyPolicy.getId();
        ISSUING_DISTRIBUTION_POINT = Extension.issuingDistributionPoint.getId();
        DELTA_CRL_INDICATOR = Extension.deltaCRLIndicator.getId();
        POLICY_CONSTRAINTS = Extension.policyConstraints.getId();
        FRESHEST_CRL = Extension.freshestCRL.getId();
        CRL_DISTRIBUTION_POINTS = Extension.cRLDistributionPoints.getId();
        AUTHORITY_KEY_IDENTIFIER = Extension.authorityKeyIdentifier.getId();
        CRL_NUMBER = Extension.cRLNumber.getId();
        crlReasons = new String[]{"unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "unknown", "removeFromCRL", "privilegeWithdrawn", "aACompromise"};
    }
}
