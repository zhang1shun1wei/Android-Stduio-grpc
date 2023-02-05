package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;
import java.util.Hashtable;

public class PolicyMappings extends ASN1Object {
    ASN1Sequence seq = null;

    public static PolicyMappings getInstance(Object obj) {
        if (obj instanceof PolicyMappings) {
            return (PolicyMappings) obj;
        }
        if (obj != null) {
            return new PolicyMappings(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private PolicyMappings(ASN1Sequence seq2) {
        this.seq = seq2;
    }

    public PolicyMappings(Hashtable mappings) {
        ASN1EncodableVector dev = new ASN1EncodableVector(mappings.size());
        Enumeration it = mappings.keys();
        while (it.hasMoreElements()) {
            String idp = (String) it.nextElement();
            ASN1EncodableVector dv = new ASN1EncodableVector(2);
            dv.add(new ASN1ObjectIdentifier(idp));
            dv.add(new ASN1ObjectIdentifier((String) mappings.get(idp)));
            dev.add(new DERSequence(dv));
        }
        this.seq = new DERSequence(dev);
    }

    public PolicyMappings(CertPolicyId issuerDomainPolicy, CertPolicyId subjectDomainPolicy) {
        ASN1EncodableVector dv = new ASN1EncodableVector(2);
        dv.add(issuerDomainPolicy);
        dv.add(subjectDomainPolicy);
        this.seq = new DERSequence(new DERSequence(dv));
    }

    public PolicyMappings(CertPolicyId[] issuerDomainPolicy, CertPolicyId[] subjectDomainPolicy) {
        ASN1EncodableVector dev = new ASN1EncodableVector(issuerDomainPolicy.length);
        for (int i = 0; i != issuerDomainPolicy.length; i++) {
            ASN1EncodableVector dv = new ASN1EncodableVector(2);
            dv.add(issuerDomainPolicy[i]);
            dv.add(subjectDomainPolicy[i]);
            dev.add(new DERSequence(dv));
        }
        this.seq = new DERSequence(dev);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.seq;
    }
}
