//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class LraPopWitness extends ASN1Object {
    private final BodyPartID pkiDataBodyid;
    private final ASN1Sequence bodyIds;

    public LraPopWitness(BodyPartID pkiDataBodyid, ASN1Sequence bodyIds) {
        this.pkiDataBodyid = pkiDataBodyid;
        this.bodyIds = bodyIds;
    }

    private LraPopWitness(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.pkiDataBodyid = BodyPartID.getInstance(seq.getObjectAt(0));
            this.bodyIds = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    public static LraPopWitness getInstance(Object o) {
        if (o instanceof LraPopWitness) {
            return (LraPopWitness)o;
        } else {
            return o != null ? new LraPopWitness(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public BodyPartID getPkiDataBodyid() {
        return this.pkiDataBodyid;
    }

    public BodyPartID[] getBodyIds() {
        BodyPartID[] rv = new BodyPartID[this.bodyIds.size()];

        for(int i = 0; i != this.bodyIds.size(); ++i) {
            rv[i] = BodyPartID.getInstance(this.bodyIds.getObjectAt(i));
        }

        return rv;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.pkiDataBodyid);
        v.add(this.bodyIds);
        return new DERSequence(v);
    }
}