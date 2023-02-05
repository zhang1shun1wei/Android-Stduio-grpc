//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class RecipientInfo extends ASN1Object implements ASN1Choice {
    ASN1Encodable info;

    public RecipientInfo(KeyTransRecipientInfo info) {
        this.info = info;
    }

    public RecipientInfo(KeyAgreeRecipientInfo info) {
        this.info = new DERTaggedObject(false, 1, info);
    }

    public RecipientInfo(KEKRecipientInfo info) {
        this.info = new DERTaggedObject(false, 2, info);
    }

    public RecipientInfo(PasswordRecipientInfo info) {
        this.info = new DERTaggedObject(false, 3, info);
    }

    public RecipientInfo(OtherRecipientInfo info) {
        this.info = new DERTaggedObject(false, 4, info);
    }

    public RecipientInfo(ASN1Primitive info) {
        this.info = info;
    }

    public static RecipientInfo getInstance(Object o) {
        if (o != null && !(o instanceof RecipientInfo)) {
            if (o instanceof ASN1Sequence) {
                return new RecipientInfo((ASN1Sequence)o);
            } else if (o instanceof ASN1TaggedObject) {
                return new RecipientInfo((ASN1TaggedObject)o);
            } else {
                throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
            }
        } else {
            return (RecipientInfo)o;
        }
    }

    public ASN1Integer getVersion() {
        if (this.info instanceof ASN1TaggedObject) {
            ASN1TaggedObject o = (ASN1TaggedObject)this.info;
            switch(o.getTagNo()) {
                case 1:
                    return KeyAgreeRecipientInfo.getInstance(o, false).getVersion();
                case 2:
                    return this.getKEKInfo(o).getVersion();
                case 3:
                    return PasswordRecipientInfo.getInstance(o, false).getVersion();
                case 4:
                    return new ASN1Integer(0L);
                default:
                    throw new IllegalStateException("unknown tag");
            }
        } else {
            return KeyTransRecipientInfo.getInstance(this.info).getVersion();
        }
    }

    public boolean isTagged() {
        return this.info instanceof ASN1TaggedObject;
    }

    public ASN1Encodable getInfo() {
        if (this.info instanceof ASN1TaggedObject) {
            ASN1TaggedObject o = (ASN1TaggedObject)this.info;
            switch(o.getTagNo()) {
                case 1:
                    return KeyAgreeRecipientInfo.getInstance(o, false);
                case 2:
                    return this.getKEKInfo(o);
                case 3:
                    return PasswordRecipientInfo.getInstance(o, false);
                case 4:
                    return OtherRecipientInfo.getInstance(o, false);
                default:
                    throw new IllegalStateException("unknown tag");
            }
        } else {
            return KeyTransRecipientInfo.getInstance(this.info);
        }
    }

    private KEKRecipientInfo getKEKInfo(ASN1TaggedObject o) {
        return o.isExplicit() ? KEKRecipientInfo.getInstance(o, true) : KEKRecipientInfo.getInstance(o, false);
    }

    public ASN1Primitive toASN1Primitive() {
        return this.info.toASN1Primitive();
    }
}
