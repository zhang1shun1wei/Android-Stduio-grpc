//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.CertificateList;

public class TimeStampAndCRL extends ASN1Object {
    private ContentInfo timeStamp;
    private CertificateList crl;

    public TimeStampAndCRL(ContentInfo timeStamp) {
        this.timeStamp = timeStamp;
    }

    private TimeStampAndCRL(ASN1Sequence seq) {
        this.timeStamp = ContentInfo.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2) {
            this.crl = CertificateList.getInstance(seq.getObjectAt(1));
        }

    }

    public static TimeStampAndCRL getInstance(Object obj) {
        if (obj instanceof TimeStampAndCRL) {
            return (TimeStampAndCRL)obj;
        } else {
            return obj != null ? new TimeStampAndCRL(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ContentInfo getTimeStampToken() {
        return this.timeStamp;
    }

    /** @deprecated */
    public CertificateList getCertificateList() {
        return this.crl;
    }

    public CertificateList getCRL() {
        return this.crl;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.timeStamp);
        if (this.crl != null) {
            v.add(this.crl);
        }

        return new DERSequence(v);
    }
}
