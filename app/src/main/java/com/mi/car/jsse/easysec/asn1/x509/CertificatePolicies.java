package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class CertificatePolicies extends ASN1Object {
    private final PolicyInformation[] policyInformation;

    private static PolicyInformation[] copy(PolicyInformation[] policyInfo) {
        PolicyInformation[] result = new PolicyInformation[policyInfo.length];
        System.arraycopy(policyInfo, 0, result, 0, policyInfo.length);
        return result;
    }

    public static CertificatePolicies getInstance(Object obj) {
        if (obj instanceof CertificatePolicies) {
            return (CertificatePolicies) obj;
        }
        if (obj != null) {
            return new CertificatePolicies(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static CertificatePolicies getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertificatePolicies fromExtensions(Extensions extensions) {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.certificatePolicies));
    }

    public CertificatePolicies(PolicyInformation name) {
        this.policyInformation = new PolicyInformation[]{name};
    }

    public CertificatePolicies(PolicyInformation[] policyInformation2) {
        this.policyInformation = copy(policyInformation2);
    }

    private CertificatePolicies(ASN1Sequence seq) {
        this.policyInformation = new PolicyInformation[seq.size()];
        for (int i = 0; i != seq.size(); i++) {
            this.policyInformation[i] = PolicyInformation.getInstance(seq.getObjectAt(i));
        }
    }

    public PolicyInformation[] getPolicyInformation() {
        return copy(this.policyInformation);
    }

    public PolicyInformation getPolicyInformation(ASN1ObjectIdentifier policyIdentifier) {
        for (int i = 0; i != this.policyInformation.length; i++) {
            if (policyIdentifier.equals((ASN1Primitive) this.policyInformation[i].getPolicyIdentifier())) {
                return this.policyInformation[i];
            }
        }
        return null;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(this.policyInformation);
    }

    public String toString() {
        StringBuffer p = new StringBuffer();
        for (int i = 0; i < this.policyInformation.length; i++) {
            if (p.length() != 0) {
                p.append(", ");
            }
            p.append(this.policyInformation[i]);
        }
        return "CertificatePolicies: [" + ((Object) p) + "]";
    }
}
