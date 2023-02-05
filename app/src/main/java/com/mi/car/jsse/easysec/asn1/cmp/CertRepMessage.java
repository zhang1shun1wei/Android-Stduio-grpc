//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class CertRepMessage extends ASN1Object {
    private ASN1Sequence caPubs;
    private final ASN1Sequence response;

    private CertRepMessage(ASN1Sequence seq) {
        int index = 0;
        if (seq.size() > 1) {
            this.caPubs = ASN1Sequence.getInstance((ASN1TaggedObject)seq.getObjectAt(index++), true);
        }

        this.response = ASN1Sequence.getInstance(seq.getObjectAt(index));
    }

    public CertRepMessage(CMPCertificate[] caPubs, CertResponse[] response) {
        if (response == null) {
            throw new IllegalArgumentException("'response' cannot be null");
        } else {
            if (caPubs != null) {
                this.caPubs = new DERSequence(caPubs);
            }

            this.response = new DERSequence(response);
        }
    }

    public static CertRepMessage getInstance(Object o) {
        if (o instanceof CertRepMessage) {
            return (CertRepMessage)o;
        } else {
            return o != null ? new CertRepMessage(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public CMPCertificate[] getCaPubs() {
        if (this.caPubs == null) {
            return null;
        } else {
            CMPCertificate[] results = new CMPCertificate[this.caPubs.size()];

            for(int i = 0; i != results.length; ++i) {
                results[i] = CMPCertificate.getInstance(this.caPubs.getObjectAt(i));
            }

            return results;
        }
    }

    public CertResponse[] getResponse() {
        CertResponse[] results = new CertResponse[this.response.size()];

        for(int i = 0; i != results.length; ++i) {
            results[i] = CertResponse.getInstance(this.response.getObjectAt(i));
        }

        return results;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this.caPubs != null) {
            v.add(new DERTaggedObject(true, 1, this.caPubs));
        }

        v.add(this.response);
        return new DERSequence(v);
    }
}
