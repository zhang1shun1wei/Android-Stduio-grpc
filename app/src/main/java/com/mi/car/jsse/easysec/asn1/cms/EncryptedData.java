//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.BERTaggedObject;

public class EncryptedData extends ASN1Object {
    private ASN1Integer version;
    private EncryptedContentInfo encryptedContentInfo;
    private ASN1Set unprotectedAttrs;

    public static EncryptedData getInstance(Object o) {
        if (o instanceof EncryptedData) {
            return (EncryptedData)o;
        } else {
            return o != null ? new EncryptedData(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public EncryptedData(EncryptedContentInfo encInfo) {
        this(encInfo, (ASN1Set)null);
    }

    public EncryptedData(EncryptedContentInfo encInfo, ASN1Set unprotectedAttrs) {
        this.version = new ASN1Integer(unprotectedAttrs == null ? 0L : 2L);
        this.encryptedContentInfo = encInfo;
        this.unprotectedAttrs = unprotectedAttrs;
    }

    private EncryptedData(ASN1Sequence seq) {
        this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
        this.encryptedContentInfo = EncryptedContentInfo.getInstance(seq.getObjectAt(1));
        if (seq.size() == 3) {
            this.unprotectedAttrs = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(2), false);
        }

    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public EncryptedContentInfo getEncryptedContentInfo() {
        return this.encryptedContentInfo;
    }

    public ASN1Set getUnprotectedAttrs() {
        return this.unprotectedAttrs;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.version);
        v.add(this.encryptedContentInfo);
        if (this.unprotectedAttrs != null) {
            v.add(new BERTaggedObject(false, 1, this.unprotectedAttrs));
        }

        return new BERSequence(v);
    }
}
