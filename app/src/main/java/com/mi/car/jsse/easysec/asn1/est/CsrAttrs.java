package com.mi.car.jsse.easysec.asn1.est;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class CsrAttrs extends ASN1Object {
    private final AttrOrOID[] attrOrOIDs;

    public static CsrAttrs getInstance(Object obj) {
        if (obj instanceof CsrAttrs) {
            return (CsrAttrs) obj;
        }
        if (obj != null) {
            return new CsrAttrs(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static CsrAttrs getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public CsrAttrs(AttrOrOID attrOrOID) {
        this.attrOrOIDs = new AttrOrOID[]{attrOrOID};
    }

    public CsrAttrs(AttrOrOID[] attrOrOIDs2) {
        this.attrOrOIDs = Utils.clone(attrOrOIDs2);
    }

    private CsrAttrs(ASN1Sequence seq) {
        this.attrOrOIDs = new AttrOrOID[seq.size()];
        for (int i = 0; i != seq.size(); i++) {
            this.attrOrOIDs[i] = AttrOrOID.getInstance(seq.getObjectAt(i));
        }
    }

    public AttrOrOID[] getAttrOrOIDs() {
        return Utils.clone(this.attrOrOIDs);
    }

    public int size() {
        return this.attrOrOIDs.length;
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(this.attrOrOIDs);
    }
}
