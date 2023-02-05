package com.mi.car.jsse.easysec.asn1.ess;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.PolicyInformation;

public class SigningCertificate extends ASN1Object {
    ASN1Sequence certs;
    ASN1Sequence policies;

    public static SigningCertificate getInstance(Object o) {
        if (o instanceof SigningCertificate) {
            return (SigningCertificate) o;
        }
        if (o != null) {
            return new SigningCertificate(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private SigningCertificate(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.certs = ASN1Sequence.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.policies = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    public SigningCertificate(ESSCertID essCertID) {
        this.certs = new DERSequence(essCertID);
    }

    public ESSCertID[] getCerts() {
        ESSCertID[] cs = new ESSCertID[this.certs.size()];
        for (int i = 0; i != this.certs.size(); i++) {
            cs[i] = ESSCertID.getInstance(this.certs.getObjectAt(i));
        }
        return cs;
    }

    public PolicyInformation[] getPolicies() {
        if (this.policies == null) {
            return null;
        }
        PolicyInformation[] ps = new PolicyInformation[this.policies.size()];
        for (int i = 0; i != this.policies.size(); i++) {
            ps[i] = PolicyInformation.getInstance(this.policies.getObjectAt(i));
        }
        return ps;
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
