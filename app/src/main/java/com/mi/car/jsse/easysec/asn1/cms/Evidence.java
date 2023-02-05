//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.tsp.EvidenceRecord;

public class Evidence extends ASN1Object implements ASN1Choice {
    private TimeStampTokenEvidence tstEvidence;
    private EvidenceRecord ersEvidence;
    private ASN1Sequence otherEvidence;

    public Evidence(TimeStampTokenEvidence tstEvidence) {
        this.tstEvidence = tstEvidence;
    }

    public Evidence(EvidenceRecord ersEvidence) {
        this.ersEvidence = ersEvidence;
    }

    private Evidence(ASN1TaggedObject tagged) {
        if (tagged.getTagNo() == 0) {
            this.tstEvidence = TimeStampTokenEvidence.getInstance(tagged, false);
        } else if (tagged.getTagNo() == 1) {
            this.ersEvidence = EvidenceRecord.getInstance(tagged, false);
        } else {
            if (tagged.getTagNo() != 2) {
                throw new IllegalArgumentException("unknown tag in Evidence");
            }

            this.otherEvidence = ASN1Sequence.getInstance(tagged, false);
        }

    }

    public static Evidence getInstance(Object obj) {
        if (obj != null && !(obj instanceof Evidence)) {
            if (obj instanceof ASN1TaggedObject) {
                return new Evidence(ASN1TaggedObject.getInstance(obj));
            } else {
                throw new IllegalArgumentException("unknown object in getInstance");
            }
        } else {
            return (Evidence)obj;
        }
    }

    public static Evidence getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    public TimeStampTokenEvidence getTstEvidence() {
        return this.tstEvidence;
    }

    public EvidenceRecord getErsEvidence() {
        return this.ersEvidence;
    }

    public ASN1Primitive toASN1Primitive() {
        if (this.tstEvidence != null) {
            return new DERTaggedObject(false, 0, this.tstEvidence);
        } else {
            return this.ersEvidence != null ? new DERTaggedObject(false, 1, this.ersEvidence) : new DERTaggedObject(false, 2, this.otherEvidence);
        }
    }
}
