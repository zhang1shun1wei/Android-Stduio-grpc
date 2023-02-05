//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class CAKeyUpdAnnContent extends ASN1Object {
    private final CMPCertificate oldWithNew;
    private final CMPCertificate newWithOld;
    private final CMPCertificate newWithNew;

    private CAKeyUpdAnnContent(ASN1Sequence seq) {
        this.oldWithNew = CMPCertificate.getInstance(seq.getObjectAt(0));
        this.newWithOld = CMPCertificate.getInstance(seq.getObjectAt(1));
        this.newWithNew = CMPCertificate.getInstance(seq.getObjectAt(2));
    }

    public CAKeyUpdAnnContent(CMPCertificate oldWithNew, CMPCertificate newWithOld, CMPCertificate newWithNew) {
        this.oldWithNew = oldWithNew;
        this.newWithOld = newWithOld;
        this.newWithNew = newWithNew;
    }

    public static CAKeyUpdAnnContent getInstance(Object o) {
        if (o instanceof CAKeyUpdAnnContent) {
            return (CAKeyUpdAnnContent)o;
        } else {
            return o != null ? new CAKeyUpdAnnContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public CMPCertificate getOldWithNew() {
        return this.oldWithNew;
    }

    public CMPCertificate getNewWithOld() {
        return this.newWithOld;
    }

    public CMPCertificate getNewWithNew() {
        return this.newWithNew;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.oldWithNew);
        v.add(this.newWithOld);
        v.add(this.newWithNew);
        return new DERSequence(v);
    }
}
