//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.crmf.CertTemplate;

public class CertReqTemplateContent extends ASN1Object {
    private final CertTemplate certTemplate;
    private final ASN1Sequence keySpec;

    private CertReqTemplateContent(ASN1Sequence seq) {
        if (seq.size() != 1 && seq.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 1 or 2");
        } else {
            this.certTemplate = CertTemplate.getInstance(seq.getObjectAt(0));
            if (seq.size() > 1) {
                this.keySpec = ASN1Sequence.getInstance(seq.getObjectAt(1));
            } else {
                this.keySpec = null;
            }

        }
    }

    public CertReqTemplateContent(CertTemplate certTemplate, ASN1Sequence keySpec) {
        this.certTemplate = certTemplate;
        this.keySpec = keySpec;
    }

    public static CertReqTemplateContent getInstance(Object o) {
        if (o instanceof CertReqTemplateContent) {
            return (CertReqTemplateContent)o;
        } else {
            return o != null ? new CertReqTemplateContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public CertTemplate getCertTemplate() {
        return this.certTemplate;
    }

    public ASN1Sequence getKeySpec() {
        return this.keySpec;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.certTemplate);
        if (this.keySpec != null) {
            v.add(this.keySpec);
        }

        return new DERSequence(v);
    }
}
