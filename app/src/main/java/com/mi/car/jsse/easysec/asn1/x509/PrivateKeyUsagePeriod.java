package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.util.Enumeration;

public class PrivateKeyUsagePeriod extends ASN1Object {
    private ASN1GeneralizedTime _notAfter;
    private ASN1GeneralizedTime _notBefore;

    public static PrivateKeyUsagePeriod getInstance(Object obj) {
        if (obj instanceof PrivateKeyUsagePeriod) {
            return (PrivateKeyUsagePeriod) obj;
        }
        if (obj != null) {
            return new PrivateKeyUsagePeriod(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private PrivateKeyUsagePeriod(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        while (en.hasMoreElements()) {
            ASN1TaggedObject tObj = (ASN1TaggedObject) en.nextElement();
            if (tObj.getTagNo() == 0) {
                this._notBefore = ASN1GeneralizedTime.getInstance(tObj, false);
            } else if (tObj.getTagNo() == 1) {
                this._notAfter = ASN1GeneralizedTime.getInstance(tObj, false);
            }
        }
    }

    public ASN1GeneralizedTime getNotBefore() {
        return this._notBefore;
    }

    public ASN1GeneralizedTime getNotAfter() {
        return this._notAfter;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this._notBefore != null) {
            v.add(new DERTaggedObject(false, 0, (ASN1Encodable) this._notBefore));
        }
        if (this._notAfter != null) {
            v.add(new DERTaggedObject(false, 1, (ASN1Encodable) this._notAfter));
        }
        return new DERSequence(v);
    }
}
