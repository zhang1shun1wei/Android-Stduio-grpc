package com.mi.car.jsse.easysec.asn1.ocsp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1IA5String;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERIA5String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.util.Enumeration;

public class CrlID extends ASN1Object {
    private ASN1Integer crlNum;
    private ASN1GeneralizedTime crlTime;
    private ASN1IA5String crlUrl;

    private CrlID(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1TaggedObject o = (ASN1TaggedObject) e.nextElement();
            switch (o.getTagNo()) {
                case 0:
                    this.crlUrl = ASN1IA5String.getInstance(o, true);
                    break;
                case 1:
                    this.crlNum = ASN1Integer.getInstance(o, true);
                    break;
                case 2:
                    this.crlTime = ASN1GeneralizedTime.getInstance(o, true);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag number: " + o.getTagNo());
            }
        }
    }

    public static CrlID getInstance(Object obj) {
        if (obj instanceof CrlID) {
            return (CrlID) obj;
        }
        if (obj != null) {
            return new CrlID(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DERIA5String getCrlUrl() {
        if (this.crlUrl == null || (this.crlUrl instanceof DERIA5String)) {
            return (DERIA5String) this.crlUrl;
        }
        return new DERIA5String(this.crlUrl.getString(), false);
    }

    public ASN1IA5String getCrlUrlIA5() {
        return this.crlUrl;
    }

    public ASN1Integer getCrlNum() {
        return this.crlNum;
    }

    public ASN1GeneralizedTime getCrlTime() {
        return this.crlTime;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        if (this.crlUrl != null) {
            v.add(new DERTaggedObject(true, 0, (ASN1Encodable) this.crlUrl));
        }
        if (this.crlNum != null) {
            v.add(new DERTaggedObject(true, 1, (ASN1Encodable) this.crlNum));
        }
        if (this.crlTime != null) {
            v.add(new DERTaggedObject(true, 2, (ASN1Encodable) this.crlTime));
        }
        return new DERSequence(v);
    }
}
