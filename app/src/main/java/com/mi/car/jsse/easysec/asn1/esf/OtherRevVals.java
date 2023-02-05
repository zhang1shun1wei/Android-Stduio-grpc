package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.io.IOException;

public class OtherRevVals extends ASN1Object {
    private ASN1ObjectIdentifier otherRevValType;
    private ASN1Encodable otherRevVals;

    public static OtherRevVals getInstance(Object obj) {
        if (obj instanceof OtherRevVals) {
            return (OtherRevVals)obj;
        } else {
            return obj != null ? new OtherRevVals(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    private OtherRevVals(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        } else {
            this.otherRevValType = (ASN1ObjectIdentifier)seq.getObjectAt(0);

            try {
                this.otherRevVals = ASN1Primitive.fromByteArray(seq.getObjectAt(1).toASN1Primitive().getEncoded("DER"));
            } catch (IOException var3) {
                throw new IllegalStateException();
            }
        }
    }

    public OtherRevVals(ASN1ObjectIdentifier otherRevValType, ASN1Encodable otherRevVals) {
        this.otherRevValType = otherRevValType;
        this.otherRevVals = otherRevVals;
    }

    public ASN1ObjectIdentifier getOtherRevValType() {
        return this.otherRevValType;
    }

    public ASN1Encodable getOtherRevVals() {
        return this.otherRevVals;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.otherRevValType);
        v.add(this.otherRevVals);
        return new DERSequence(v);
    }
}
