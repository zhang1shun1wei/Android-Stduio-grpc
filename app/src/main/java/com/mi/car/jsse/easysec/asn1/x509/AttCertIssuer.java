package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class AttCertIssuer extends ASN1Object implements ASN1Choice {
    ASN1Primitive choiceObj;
    ASN1Encodable obj;

    public static AttCertIssuer getInstance(Object obj2) {
        if (obj2 == null || (obj2 instanceof AttCertIssuer)) {
            return (AttCertIssuer) obj2;
        }
        if (obj2 instanceof V2Form) {
            return new AttCertIssuer(V2Form.getInstance(obj2));
        }
        if (obj2 instanceof GeneralNames) {
            return new AttCertIssuer((GeneralNames) obj2);
        }
        if (obj2 instanceof ASN1TaggedObject) {
            return new AttCertIssuer(V2Form.getInstance((ASN1TaggedObject) obj2, false));
        }
        if (obj2 instanceof ASN1Sequence) {
            return new AttCertIssuer(GeneralNames.getInstance(obj2));
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj2.getClass().getName());
    }

    public static AttCertIssuer getInstance(ASN1TaggedObject obj2, boolean explicit) {
        return getInstance(obj2.getObject());
    }

    public AttCertIssuer(GeneralNames names) {
        this.obj = names;
        this.choiceObj = this.obj.toASN1Primitive();
    }

    public AttCertIssuer(V2Form v2Form) {
        this.obj = v2Form;
        this.choiceObj = new DERTaggedObject(false, 0, this.obj);
    }

    public ASN1Encodable getIssuer() {
        return this.obj;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.choiceObj;
    }
}
