//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Arrays;

public class DecryptedPOP extends ASN1Object {
    private final BodyPartID bodyPartID;
    private final AlgorithmIdentifier thePOPAlgID;
    private final byte[] thePOP;

    public DecryptedPOP(BodyPartID bodyPartID, AlgorithmIdentifier thePOPAlgID, byte[] thePOP) {
        this.bodyPartID = bodyPartID;
        this.thePOPAlgID = thePOPAlgID;
        this.thePOP = Arrays.clone(thePOP);
    }

    private DecryptedPOP(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
            this.thePOPAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            this.thePOP = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
        }
    }

    public static DecryptedPOP getInstance(Object o) {
        if (o instanceof DecryptedPOP) {
            return (DecryptedPOP)o;
        } else {
            return o != null ? new DecryptedPOP(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public BodyPartID getBodyPartID() {
        return this.bodyPartID;
    }

    public AlgorithmIdentifier getThePOPAlgID() {
        return this.thePOPAlgID;
    }

    public byte[] getThePOP() {
        return Arrays.clone(this.thePOP);
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.bodyPartID);
        v.add(this.thePOPAlgID);
        v.add(new DEROctetString(this.thePOP));
        return new DERSequence(v);
    }
}