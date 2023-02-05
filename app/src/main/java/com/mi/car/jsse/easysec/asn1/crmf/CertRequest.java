package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class CertRequest extends ASN1Object {
    private ASN1Integer certReqId;
    private CertTemplate certTemplate;
    private Controls controls;

    private CertRequest(ASN1Sequence seq) {
        this.certReqId = new ASN1Integer(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        this.certTemplate = CertTemplate.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            this.controls = Controls.getInstance(seq.getObjectAt(2));
        }
    }

    public static CertRequest getInstance(Object o) {
        if (o instanceof CertRequest) {
            return (CertRequest) o;
        }
        if (o != null) {
            return new CertRequest(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public CertRequest(int certReqId2, CertTemplate certTemplate2, Controls controls2) {
        this(new ASN1Integer((long) certReqId2), certTemplate2, controls2);
    }

    public CertRequest(ASN1Integer certReqId2, CertTemplate certTemplate2, Controls controls2) {
        this.certReqId = certReqId2;
        this.certTemplate = certTemplate2;
        this.controls = controls2;
    }

    public ASN1Integer getCertReqId() {
        return this.certReqId;
    }

    public CertTemplate getCertTemplate() {
        return this.certTemplate;
    }

    public Controls getControls() {
        return this.controls;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.certReqId);
        v.add(this.certTemplate);
        if (this.controls != null) {
            v.add(this.controls);
        }
        return new DERSequence(v);
    }
}
