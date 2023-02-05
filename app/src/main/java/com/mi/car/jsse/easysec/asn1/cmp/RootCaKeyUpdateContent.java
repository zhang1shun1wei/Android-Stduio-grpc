//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.util.Iterator;

public class RootCaKeyUpdateContent extends ASN1Object {
    private final CMPCertificate newWithNew;
    private final CMPCertificate newWithOld;
    private final CMPCertificate oldWithNew;

    public RootCaKeyUpdateContent(CMPCertificate newWithMew, CMPCertificate newWithOld, CMPCertificate oldWithNew) {
        this.newWithNew = newWithMew;
        this.newWithOld = newWithOld;
        this.oldWithNew = oldWithNew;
    }

    private RootCaKeyUpdateContent(ASN1Sequence seq) {
        if (seq.size() >= 1 && seq.size() <= 3) {
            CMPCertificate newWithOld = null;
            CMPCertificate oldWithNew = null;
            Iterator<ASN1Encodable> encodable = seq.iterator();
            CMPCertificate newWithNew = CMPCertificate.getInstance(encodable.next());

            while(encodable.hasNext()) {
                ASN1TaggedObject ato = ASN1TaggedObject.getInstance(encodable.next());
                if (ato.getTagNo() == 0) {
                    newWithOld = CMPCertificate.getInstance(ato, true);
                } else if (ato.getTagNo() == 1) {
                    oldWithNew = CMPCertificate.getInstance(ato, true);
                }
            }

            this.newWithNew = newWithNew;
            this.newWithOld = newWithOld;
            this.oldWithNew = oldWithNew;
        } else {
            throw new IllegalArgumentException("expected sequence of 1 to 3 elements only");
        }
    }

    public static RootCaKeyUpdateContent getInstance(Object o) {
        if (o instanceof RootCaKeyUpdateContent) {
            return (RootCaKeyUpdateContent)o;
        } else {
            return o != null ? new RootCaKeyUpdateContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public CMPCertificate getNewWithNew() {
        return this.newWithNew;
    }

    public CMPCertificate getNewWithOld() {
        return this.newWithOld;
    }

    public CMPCertificate getOldWithNew() {
        return this.oldWithNew;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector avec = new ASN1EncodableVector();
        avec.add(this.newWithNew);
        if (this.newWithOld != null) {
            avec.add(new DERTaggedObject(true, 0, this.newWithOld));
        }

        if (this.oldWithNew != null) {
            avec.add(new DERTaggedObject(true, 1, this.oldWithNew));
        }

        return new DERSequence(avec);
    }
}
