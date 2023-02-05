package com.mi.car.jsse.easysec.asn1.dvcs;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.io.IOException;

public class DVCSResponse extends ASN1Object implements ASN1Choice {
    private DVCSCertInfo dvCertInfo;
    private DVCSErrorNotice dvErrorNote;

    public DVCSResponse(DVCSCertInfo dvCertInfo2) {
        this.dvCertInfo = dvCertInfo2;
    }

    public DVCSResponse(DVCSErrorNotice dvErrorNote2) {
        this.dvErrorNote = dvErrorNote2;
    }

    public static DVCSResponse getInstance(Object obj) {
        if (obj == null || (obj instanceof DVCSResponse)) {
            return (DVCSResponse) obj;
        }
        if (obj instanceof byte[]) {
            try {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct sequence from byte[]: " + e.getMessage());
            }
        } else if (obj instanceof ASN1Sequence) {
            return new DVCSResponse(DVCSCertInfo.getInstance(obj));
        } else {
            if (obj instanceof ASN1TaggedObject) {
                return new DVCSResponse(DVCSErrorNotice.getInstance(ASN1TaggedObject.getInstance(obj), false));
            }
            throw new IllegalArgumentException("Couldn't convert from object to DVCSResponse: " + obj.getClass().getName());
        }
    }

    public static DVCSResponse getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public DVCSCertInfo getCertInfo() {
        return this.dvCertInfo;
    }

    public DVCSErrorNotice getErrorNotice() {
        return this.dvErrorNote;
    }

    public ASN1Primitive toASN1Primitive() {
        if (this.dvCertInfo != null) {
            return this.dvCertInfo.toASN1Primitive();
        }
        return new DERTaggedObject(false, 0, this.dvErrorNote);
    }

    public String toString() {
        if (this.dvCertInfo != null) {
            return "DVCSResponse {\ndvCertInfo: " + this.dvCertInfo.toString() + "}\n";
        }
        return "DVCSResponse {\ndvErrorNote: " + this.dvErrorNote.toString() + "}\n";
    }
}
