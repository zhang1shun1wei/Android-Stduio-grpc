package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class OtherName extends ASN1Object {
    private final ASN1ObjectIdentifier typeID;
    private final ASN1Encodable value;

    public static OtherName getInstance(Object obj) {
        if (obj instanceof OtherName) {
            return (OtherName) obj;
        }
        if (obj != null) {
            return new OtherName(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public OtherName(ASN1ObjectIdentifier typeID2, ASN1Encodable value2) {
        this.typeID = typeID2;
        this.value = value2;
    }

    private OtherName(ASN1Sequence seq) {
        this.typeID = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.value = ASN1TaggedObject.getInstance(seq.getObjectAt(1)).getObject();
    }

    public ASN1ObjectIdentifier getTypeID() {
        return this.typeID;
    }

    public ASN1Encodable getValue() {
        return this.value;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.typeID);
        v.add(new DERTaggedObject(true, 0, this.value));
        return new DERSequence(v);
    }
}
