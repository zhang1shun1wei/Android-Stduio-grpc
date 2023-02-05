package com.mi.car.jsse.easysec.asn1.ocsp;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Null;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.ASN1Util;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class CertStatus extends ASN1Object implements ASN1Choice {
    private int tagNo;
    private ASN1Encodable value;

    public CertStatus() {
        this.tagNo = 0;
        this.value = DERNull.INSTANCE;
    }

    public CertStatus(RevokedInfo info) {
        this.tagNo = 1;
        this.value = info;
    }

    public CertStatus(int tagNo2, ASN1Encodable value2) {
        this.tagNo = tagNo2;
        this.value = value2;
    }

    private CertStatus(ASN1TaggedObject choice) {
        int tagNo2 = choice.getTagNo();
        switch (tagNo2) {
            case 0:
                this.value = ASN1Null.getInstance(choice, false);
                break;
            case 1:
                this.value = RevokedInfo.getInstance(choice, false);
                break;
            case 2:
                this.value = ASN1Null.getInstance(choice, false);
                break;
            default:
                throw new IllegalArgumentException("Unknown tag encountered: " + ASN1Util.getTagText(choice));
        }
        this.tagNo = tagNo2;
    }

    public static CertStatus getInstance(Object obj) {
        if (obj == null || (obj instanceof CertStatus)) {
            return (CertStatus) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            return new CertStatus((ASN1TaggedObject) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public static CertStatus getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    public int getTagNo() {
        return this.tagNo;
    }

    public ASN1Encodable getStatus() {
        return this.value;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(false, this.tagNo, this.value);
    }
}
