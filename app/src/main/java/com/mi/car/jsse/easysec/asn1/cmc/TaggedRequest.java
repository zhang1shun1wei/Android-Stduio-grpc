//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.crmf.CertReqMsg;
import java.io.IOException;

public class TaggedRequest extends ASN1Object implements ASN1Choice {
    public static final int TCR = 0;
    public static final int CRM = 1;
    public static final int ORM = 2;
    private final int tagNo;
    private final ASN1Encodable value;

    public TaggedRequest(TaggedCertificationRequest tcr) {
        this.tagNo = 0;
        this.value = tcr;
    }

    public TaggedRequest(CertReqMsg crm) {
        this.tagNo = 1;
        this.value = crm;
    }

    private TaggedRequest(ASN1Sequence orm) {
        this.tagNo = 2;
        this.value = orm;
    }

    public static TaggedRequest getInstance(Object obj) {
        if (obj instanceof TaggedRequest) {
            return (TaggedRequest)obj;
        } else if (obj != null) {
            if (obj instanceof ASN1Encodable) {
                ASN1TaggedObject asn1Prim = ASN1TaggedObject.getInstance(((ASN1Encodable)obj).toASN1Primitive());
                switch(asn1Prim.getTagNo()) {
                    case 0:
                        return new TaggedRequest(TaggedCertificationRequest.getInstance(asn1Prim, false));
                    case 1:
                        return new TaggedRequest(CertReqMsg.getInstance(asn1Prim, false));
                    case 2:
                        return new TaggedRequest(ASN1Sequence.getInstance(asn1Prim, false));
                    default:
                        throw new IllegalArgumentException("unknown tag in getInstance(): " + asn1Prim.getTagNo());
                }
            } else if (obj instanceof byte[]) {
                try {
                    return getInstance(ASN1Primitive.fromByteArray((byte[])((byte[])obj)));
                } catch (IOException var2) {
                    throw new IllegalArgumentException("unknown encoding in getInstance()");
                }
            } else {
                throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
            }
        } else {
            return null;
        }
    }

    public int getTagNo() {
        return this.tagNo;
    }

    public ASN1Encodable getValue() {
        return this.value;
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(false, this.tagNo, this.value);
    }
}