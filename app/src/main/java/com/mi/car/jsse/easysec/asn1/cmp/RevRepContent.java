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
import com.mi.car.jsse.easysec.asn1.crmf.CertId;
import com.mi.car.jsse.easysec.asn1.x509.CertificateList;
import java.util.Enumeration;

public class RevRepContent extends ASN1Object {
    private final ASN1Sequence status;
    private ASN1Sequence revCerts;
    private ASN1Sequence crls;

    private RevRepContent(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        this.status = ASN1Sequence.getInstance(en.nextElement());

        while(en.hasMoreElements()) {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(en.nextElement());
            if (tObj.getTagNo() == 0) {
                this.revCerts = ASN1Sequence.getInstance(tObj, true);
            } else {
                this.crls = ASN1Sequence.getInstance(tObj, true);
            }
        }

    }

    public static RevRepContent getInstance(Object o) {
        if (o instanceof RevRepContent) {
            return (RevRepContent)o;
        } else {
            return o != null ? new RevRepContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public PKIStatusInfo[] getStatus() {
        PKIStatusInfo[] results = new PKIStatusInfo[this.status.size()];

        for(int i = 0; i != results.length; ++i) {
            results[i] = PKIStatusInfo.getInstance(this.status.getObjectAt(i));
        }

        return results;
    }

    public CertId[] getRevCerts() {
        if (this.revCerts == null) {
            return null;
        } else {
            CertId[] results = new CertId[this.revCerts.size()];

            for(int i = 0; i != results.length; ++i) {
                results[i] = CertId.getInstance(this.revCerts.getObjectAt(i));
            }

            return results;
        }
    }

    public CertificateList[] getCrls() {
        if (this.crls == null) {
            return null;
        } else {
            CertificateList[] results = new CertificateList[this.crls.size()];

            for(int i = 0; i != results.length; ++i) {
                results[i] = CertificateList.getInstance(this.crls.getObjectAt(i));
            }

            return results;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.status);
        this.addOptional(v, 0, this.revCerts);
        this.addOptional(v, 1, this.crls);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }

    }
}
