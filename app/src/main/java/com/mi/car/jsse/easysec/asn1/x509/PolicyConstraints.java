package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.math.BigInteger;

public class PolicyConstraints extends ASN1Object {
    private BigInteger inhibitPolicyMapping;
    private BigInteger requireExplicitPolicyMapping;

    public PolicyConstraints(BigInteger requireExplicitPolicyMapping2, BigInteger inhibitPolicyMapping2) {
        this.requireExplicitPolicyMapping = requireExplicitPolicyMapping2;
        this.inhibitPolicyMapping = inhibitPolicyMapping2;
    }

    private PolicyConstraints(ASN1Sequence seq) {
        for (int i = 0; i != seq.size(); i++) {
            ASN1TaggedObject to = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
            if (to.getTagNo() == 0) {
                this.requireExplicitPolicyMapping = ASN1Integer.getInstance(to, false).getValue();
            } else if (to.getTagNo() == 1) {
                this.inhibitPolicyMapping = ASN1Integer.getInstance(to, false).getValue();
            } else {
                throw new IllegalArgumentException("Unknown tag encountered.");
            }
        }
    }

    public static PolicyConstraints getInstance(Object obj) {
        if (obj instanceof PolicyConstraints) {
            return (PolicyConstraints) obj;
        }
        if (obj != null) {
            return new PolicyConstraints(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static PolicyConstraints fromExtensions(Extensions extensions) {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.policyConstraints));
    }

    public BigInteger getRequireExplicitPolicyMapping() {
        return this.requireExplicitPolicyMapping;
    }

    public BigInteger getInhibitPolicyMapping() {
        return this.inhibitPolicyMapping;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this.requireExplicitPolicyMapping != null) {
            v.add(new DERTaggedObject(false, 0, (ASN1Encodable) new ASN1Integer(this.requireExplicitPolicyMapping)));
        }
        if (this.inhibitPolicyMapping != null) {
            v.add(new DERTaggedObject(false, 1, (ASN1Encodable) new ASN1Integer(this.inhibitPolicyMapping)));
        }
        return new DERSequence(v);
    }
}
