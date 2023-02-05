package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class UserNotice extends ASN1Object {
    private final DisplayText explicitText;
    private final NoticeReference noticeRef;

    public UserNotice(NoticeReference noticeRef2, DisplayText explicitText2) {
        this.noticeRef = noticeRef2;
        this.explicitText = explicitText2;
    }

    public UserNotice(NoticeReference noticeRef2, String str) {
        this(noticeRef2, new DisplayText(str));
    }

    private UserNotice(ASN1Sequence as) {
        if (as.size() == 2) {
            this.noticeRef = NoticeReference.getInstance(as.getObjectAt(0));
            this.explicitText = DisplayText.getInstance(as.getObjectAt(1));
        } else if (as.size() == 1) {
            if (as.getObjectAt(0).toASN1Primitive() instanceof ASN1Sequence) {
                this.noticeRef = NoticeReference.getInstance(as.getObjectAt(0));
                this.explicitText = null;
                return;
            }
            this.explicitText = DisplayText.getInstance(as.getObjectAt(0));
            this.noticeRef = null;
        } else if (as.size() == 0) {
            this.noticeRef = null;
            this.explicitText = null;
        } else {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
        }
    }

    public static UserNotice getInstance(Object obj) {
        if (obj instanceof UserNotice) {
            return (UserNotice) obj;
        }
        if (obj != null) {
            return new UserNotice(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public NoticeReference getNoticeRef() {
        return this.noticeRef;
    }

    public DisplayText getExplicitText() {
        return this.explicitText;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector av = new ASN1EncodableVector(2);
        if (this.noticeRef != null) {
            av.add(this.noticeRef);
        }
        if (this.explicitText != null) {
            av.add(this.explicitText);
        }
        return new DERSequence(av);
    }
}
