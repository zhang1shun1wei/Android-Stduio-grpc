//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.CertificateList;

public class CRLAnnContent extends ASN1Object {
    private final ASN1Sequence content;

    private CRLAnnContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public CRLAnnContent(CertificateList crl) {
        this.content = new DERSequence(crl);
    }

    public static CRLAnnContent getInstance(Object o) {
        if (o instanceof CRLAnnContent) {
            return (CRLAnnContent)o;
        } else {
            return o != null ? new CRLAnnContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public CertificateList[] getCertificateLists() {
        CertificateList[] result = new CertificateList[this.content.size()];

        for(int i = 0; i != result.length; ++i) {
            result[i] = CertificateList.getInstance(this.content.getObjectAt(i));
        }

        return result;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.content;
    }
}