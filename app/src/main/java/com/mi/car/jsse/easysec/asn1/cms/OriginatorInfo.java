//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class OriginatorInfo extends ASN1Object {
    private ASN1Set certs;
    private ASN1Set crls;

    public OriginatorInfo(ASN1Set certs, ASN1Set crls) {
        this.certs = certs;
        this.crls = crls;
    }

    private OriginatorInfo(ASN1Sequence seq) {
        switch(seq.size()) {
            case 0:
                break;
            case 1:
                ASN1TaggedObject o = (ASN1TaggedObject)seq.getObjectAt(0);
                switch(o.getTagNo()) {
                    case 0:
                        this.certs = ASN1Set.getInstance(o, false);
                        return;
                    case 1:
                        this.crls = ASN1Set.getInstance(o, false);
                        return;
                    default:
                        throw new IllegalArgumentException("Bad tag in OriginatorInfo: " + o.getTagNo());
                }
            case 2:
                this.certs = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(0), false);
                this.crls = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(1), false);
                break;
            default:
                throw new IllegalArgumentException("OriginatorInfo too big");
        }

    }

    public static OriginatorInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OriginatorInfo getInstance(Object obj) {
        if (obj instanceof OriginatorInfo) {
            return (OriginatorInfo)obj;
        } else {
            return obj != null ? new OriginatorInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1Set getCertificates() {
        return this.certs;
    }

    public ASN1Set getCRLs() {
        return this.crls;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this.certs != null) {
            v.add(new DERTaggedObject(false, 0, this.certs));
        }

        if (this.crls != null) {
            v.add(new DERTaggedObject(false, 1, this.crls));
        }

        return new DERSequence(v);
    }
}
