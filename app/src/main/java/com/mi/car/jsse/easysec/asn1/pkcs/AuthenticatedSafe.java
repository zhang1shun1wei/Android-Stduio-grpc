package com.mi.car.jsse.easysec.asn1.pkcs;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.DLSequence;

public class AuthenticatedSafe extends ASN1Object {
    private ContentInfo[] info;
    private boolean isBer = true;

    private AuthenticatedSafe(ASN1Sequence seq) {
        this.info = new ContentInfo[seq.size()];
        for (int i = 0; i != this.info.length; i++) {
            this.info[i] = ContentInfo.getInstance(seq.getObjectAt(i));
        }
        this.isBer = seq instanceof BERSequence;
    }

    public static AuthenticatedSafe getInstance(Object o) {
        if (o instanceof AuthenticatedSafe) {
            return (AuthenticatedSafe) o;
        }
        if (o != null) {
            return new AuthenticatedSafe(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public AuthenticatedSafe(ContentInfo[] info2) {
        this.info = copy(info2);
    }

    public ContentInfo[] getContentInfo() {
        return copy(this.info);
    }

    private ContentInfo[] copy(ContentInfo[] infos) {
        ContentInfo[] tmp = new ContentInfo[infos.length];
        System.arraycopy(infos, 0, tmp, 0, tmp.length);
        return tmp;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        if (this.isBer) {
            return new BERSequence(this.info);
        }
        return new DLSequence(this.info);
    }
}
