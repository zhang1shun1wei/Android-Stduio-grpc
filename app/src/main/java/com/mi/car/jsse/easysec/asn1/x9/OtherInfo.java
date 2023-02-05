package com.mi.car.jsse.easysec.asn1.x9;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.util.Enumeration;

public class OtherInfo extends ASN1Object {
    private KeySpecificInfo keyInfo;
    private ASN1OctetString partyAInfo;
    private ASN1OctetString suppPubInfo;

    public OtherInfo(KeySpecificInfo keyInfo2, ASN1OctetString partyAInfo2, ASN1OctetString suppPubInfo2) {
        this.keyInfo = keyInfo2;
        this.partyAInfo = partyAInfo2;
        this.suppPubInfo = suppPubInfo2;
    }

    public static OtherInfo getInstance(Object obj) {
        if (obj instanceof OtherInfo) {
            return (OtherInfo) obj;
        }
        if (obj != null) {
            return new OtherInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private OtherInfo(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.keyInfo = KeySpecificInfo.getInstance(e.nextElement());
        while (e.hasMoreElements()) {
            ASN1TaggedObject o = (ASN1TaggedObject) e.nextElement();
            if (o.getTagNo() == 0) {
                this.partyAInfo = (ASN1OctetString) o.getObject();
            } else if (o.getTagNo() == 2) {
                this.suppPubInfo = (ASN1OctetString) o.getObject();
            }
        }
    }

    public KeySpecificInfo getKeyInfo() {
        return this.keyInfo;
    }

    public ASN1OctetString getPartyAInfo() {
        return this.partyAInfo;
    }

    public ASN1OctetString getSuppPubInfo() {
        return this.suppPubInfo;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.keyInfo);
        if (this.partyAInfo != null) {
            v.add(new DERTaggedObject(0, this.partyAInfo));
        }
        v.add(new DERTaggedObject(2, this.suppPubInfo));
        return new DERSequence(v);
    }
}
