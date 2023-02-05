package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.cms.EnvelopedData;

public class POPOPrivKey extends ASN1Object implements ASN1Choice {
    public static final int agreeMAC = 3;
    public static final int dhMAC = 2;
    public static final int encryptedKey = 4;
    public static final int subsequentMessage = 1;
    public static final int thisMessage = 0;
    private ASN1Encodable obj;
    private int tagNo;

    private POPOPrivKey(ASN1TaggedObject obj2) {
        this.tagNo = obj2.getTagNo();
        switch (this.tagNo) {
            case 0:
                this.obj = DERBitString.getInstance(obj2, false);
                return;
            case 1:
                this.obj = SubsequentMessage.valueOf(ASN1Integer.getInstance(obj2, false).intValueExact());
                return;
            case 2:
                this.obj = DERBitString.getInstance(obj2, false);
                return;
            case 3:
                this.obj = PKMACValue.getInstance(obj2, false);
                return;
            case 4:
                this.obj = EnvelopedData.getInstance(obj2, false);
                return;
            default:
                throw new IllegalArgumentException("unknown tag in POPOPrivKey");
        }
    }

    public static POPOPrivKey getInstance(Object obj2) {
        if (obj2 instanceof POPOPrivKey) {
            return (POPOPrivKey) obj2;
        }
        if (obj2 != null) {
            return new POPOPrivKey(ASN1TaggedObject.getInstance(obj2));
        }
        return null;
    }

    public static POPOPrivKey getInstance(ASN1TaggedObject obj2, boolean explicit) {
        return getInstance(ASN1TaggedObject.getInstance(obj2, true));
    }

    public POPOPrivKey(PKMACValue agreeMac) {
        this.tagNo = 3;
        this.obj = agreeMac;
    }

    public POPOPrivKey(SubsequentMessage msg) {
        this.tagNo = 1;
        this.obj = msg;
    }

    public int getType() {
        return this.tagNo;
    }

    public ASN1Encodable getValue() {
        return this.obj;
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(false, this.tagNo, this.obj);
    }
}
