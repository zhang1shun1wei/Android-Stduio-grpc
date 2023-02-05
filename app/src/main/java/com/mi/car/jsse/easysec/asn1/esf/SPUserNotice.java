package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.DisplayText;
import com.mi.car.jsse.easysec.asn1.x509.NoticeReference;
import java.util.Enumeration;

public class SPUserNotice extends ASN1Object {
    private DisplayText explicitText;
    private NoticeReference noticeRef;

    public static SPUserNotice getInstance(Object obj) {
        if (obj instanceof SPUserNotice) {
            return (SPUserNotice) obj;
        }
        if (obj != null) {
            return new SPUserNotice(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private SPUserNotice(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1Encodable object = (ASN1Encodable) e.nextElement();
            if ((object instanceof DisplayText) || (object instanceof ASN1String)) {
                this.explicitText = DisplayText.getInstance(object);
            } else if ((object instanceof NoticeReference) || (object instanceof ASN1Sequence)) {
                this.noticeRef = NoticeReference.getInstance(object);
            } else {
                throw new IllegalArgumentException("Invalid element in 'SPUserNotice': " + object.getClass().getName());
            }
        }
    }

    public SPUserNotice(NoticeReference noticeRef2, DisplayText explicitText2) {
        this.noticeRef = noticeRef2;
        this.explicitText = explicitText2;
    }

    public NoticeReference getNoticeRef() {
        return this.noticeRef;
    }

    public DisplayText getExplicitText() {
        return this.explicitText;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this.noticeRef != null) {
            v.add(this.noticeRef);
        }
        if (this.explicitText != null) {
            v.add(this.explicitText);
        }
        return new DERSequence(v);
    }
}
