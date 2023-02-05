package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;

public class CompleteRevocationRefs extends ASN1Object {
    private ASN1Sequence crlOcspRefs;

    public static CompleteRevocationRefs getInstance(Object obj) {
        if (obj instanceof CompleteRevocationRefs) {
            return (CompleteRevocationRefs) obj;
        }
        if (obj != null) {
            return new CompleteRevocationRefs(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private CompleteRevocationRefs(ASN1Sequence seq) {
        Enumeration seqEnum = seq.getObjects();
        while (seqEnum.hasMoreElements()) {
            CrlOcspRef.getInstance(seqEnum.nextElement());
        }
        this.crlOcspRefs = seq;
    }

    public CompleteRevocationRefs(CrlOcspRef[] crlOcspRefs2) {
        this.crlOcspRefs = new DERSequence(crlOcspRefs2);
    }

    public CrlOcspRef[] getCrlOcspRefs() {
        CrlOcspRef[] result = new CrlOcspRef[this.crlOcspRefs.size()];
        for (int idx = 0; idx < result.length; idx++) {
            result[idx] = CrlOcspRef.getInstance(this.crlOcspRefs.getObjectAt(idx));
        }
        return result;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.crlOcspRefs;
    }
}
