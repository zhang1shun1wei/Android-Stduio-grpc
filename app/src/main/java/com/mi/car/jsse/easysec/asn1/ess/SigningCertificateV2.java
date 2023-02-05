package com.mi.car.jsse.easysec.asn1.ess;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.PolicyInformation;

public class SigningCertificateV2 extends ASN1Object {
    ASN1Sequence certs;
    ASN1Sequence policies;

    public static SigningCertificateV2 getInstance(Object o) {
        if (o == null || (o instanceof SigningCertificateV2)) {
            return (SigningCertificateV2) o;
        }
        if (o instanceof ASN1Sequence) {
            return new SigningCertificateV2((ASN1Sequence) o);
        }
        return null;
    }

    private SigningCertificateV2(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.certs = ASN1Sequence.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.policies = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    public SigningCertificateV2(ESSCertIDv2 cert) {
        this.certs = new DERSequence(cert);
    }

    public SigningCertificateV2(ESSCertIDv2[] certs2) {
        this.certs = new DERSequence(certs2);
    }

    public SigningCertificateV2(ESSCertIDv2[] certs2, PolicyInformation[] policies2) {
        this.certs = new DERSequence(certs2);
        if (policies2 != null) {
            this.policies = new DERSequence(policies2);
        }
    }

    public ESSCertIDv2[] getCerts() {
        ESSCertIDv2[] certIds = new ESSCertIDv2[this.certs.size()];
        for (int i = 0; i != this.certs.size(); i++) {
            certIds[i] = ESSCertIDv2.getInstance(this.certs.getObjectAt(i));
        }
        return certIds;
    }

    public PolicyInformation[] getPolicies() {
        if (this.policies == null) {
            return null;
        }
        PolicyInformation[] policyInformations = new PolicyInformation[this.policies.size()];
        for (int i = 0; i != this.policies.size(); i++) {
            policyInformations[i] = PolicyInformation.getInstance(this.policies.getObjectAt(i));
        }
        return policyInformations;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.certs);
        if (this.policies != null) {
            v.add(this.policies);
        }
        return new DERSequence(v);
    }
}
