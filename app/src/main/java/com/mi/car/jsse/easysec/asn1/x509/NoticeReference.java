package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Vector;

public class NoticeReference extends ASN1Object {
    private ASN1Sequence noticeNumbers;
    private DisplayText organization;

    private static ASN1EncodableVector convertVector(Vector numbers) {
        ASN1Integer di;
        ASN1EncodableVector av = new ASN1EncodableVector(numbers.size());
        Enumeration it = numbers.elements();
        while (it.hasMoreElements()) {
            Object o = it.nextElement();
            if (o instanceof BigInteger) {
                di = new ASN1Integer((BigInteger) o);
            } else if (o instanceof Integer) {
                di = new ASN1Integer((long) ((Integer) o).intValue());
            } else {
                throw new IllegalArgumentException();
            }
            av.add(di);
        }
        return av;
    }

    public NoticeReference(String organization2, Vector numbers) {
        this(organization2, convertVector(numbers));
    }

    public NoticeReference(String organization2, ASN1EncodableVector noticeNumbers2) {
        this(new DisplayText(organization2), noticeNumbers2);
    }

    public NoticeReference(DisplayText organization2, ASN1EncodableVector noticeNumbers2) {
        this.organization = organization2;
        this.noticeNumbers = new DERSequence(noticeNumbers2);
    }

    private NoticeReference(ASN1Sequence as) {
        if (as.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
        }
        this.organization = DisplayText.getInstance(as.getObjectAt(0));
        this.noticeNumbers = ASN1Sequence.getInstance(as.getObjectAt(1));
    }

    public static NoticeReference getInstance(Object as) {
        if (as instanceof NoticeReference) {
            return (NoticeReference) as;
        }
        if (as != null) {
            return new NoticeReference(ASN1Sequence.getInstance(as));
        }
        return null;
    }

    public DisplayText getOrganization() {
        return this.organization;
    }

    public ASN1Integer[] getNoticeNumbers() {
        ASN1Integer[] tmp = new ASN1Integer[this.noticeNumbers.size()];
        for (int i = 0; i != this.noticeNumbers.size(); i++) {
            tmp[i] = ASN1Integer.getInstance(this.noticeNumbers.getObjectAt(i));
        }
        return tmp;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector av = new ASN1EncodableVector(2);
        av.add(this.organization);
        av.add(this.noticeNumbers);
        return new DERSequence(av);
    }
}
