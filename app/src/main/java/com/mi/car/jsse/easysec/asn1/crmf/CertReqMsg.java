package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;

public class CertReqMsg extends ASN1Object {
    private CertRequest certReq;
    private ProofOfPossession pop;
    private ASN1Sequence regInfo;

    private CertReqMsg(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        this.certReq = CertRequest.getInstance(en.nextElement());
        while (en.hasMoreElements()) {
            Object o = en.nextElement();
            if ((o instanceof ASN1TaggedObject) || (o instanceof ProofOfPossession)) {
                this.pop = ProofOfPossession.getInstance(o);
            } else {
                this.regInfo = ASN1Sequence.getInstance(o);
            }
        }
    }

    public static CertReqMsg getInstance(Object o) {
        if (o instanceof CertReqMsg) {
            return (CertReqMsg) o;
        }
        if (o != null) {
            return new CertReqMsg(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public static CertReqMsg getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public CertReqMsg(CertRequest certReq2, ProofOfPossession pop2, AttributeTypeAndValue[] regInfo2) {
        if (certReq2 == null) {
            throw new IllegalArgumentException("'certReq' cannot be null");
        }
        this.certReq = certReq2;
        this.pop = pop2;
        if (regInfo2 != null) {
            this.regInfo = new DERSequence(regInfo2);
        }
    }

    public CertRequest getCertReq() {
        return this.certReq;
    }

    public ProofOfPossession getPop() {
        return this.pop;
    }

    public ProofOfPossession getPopo() {
        return this.pop;
    }

    public AttributeTypeAndValue[] getRegInfo() {
        if (this.regInfo == null) {
            return null;
        }
        AttributeTypeAndValue[] results = new AttributeTypeAndValue[this.regInfo.size()];
        for (int i = 0; i != results.length; i++) {
            results[i] = AttributeTypeAndValue.getInstance(this.regInfo.getObjectAt(i));
        }
        return results;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.certReq);
        addOptional(v, this.pop);
        addOptional(v, this.regInfo);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, ASN1Encodable obj) {
        if (obj != null) {
            v.add(obj);
        }
    }
}
