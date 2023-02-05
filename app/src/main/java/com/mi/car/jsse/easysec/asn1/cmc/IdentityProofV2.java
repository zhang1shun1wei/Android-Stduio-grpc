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

public class IdentityProofV2 extends ASN1Object {
    private final AlgorithmIdentifier proofAlgID;
    private final AlgorithmIdentifier macAlgId;
    private final byte[] witness;

    public IdentityProofV2(AlgorithmIdentifier proofAlgID, AlgorithmIdentifier macAlgId, byte[] witness) {
        this.proofAlgID = proofAlgID;
        this.macAlgId = macAlgId;
        this.witness = Arrays.clone(witness);
    }

    private IdentityProofV2(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.proofAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
            this.macAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            this.witness = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
        }
    }

    public static IdentityProofV2 getInstance(Object o) {
        if (o instanceof IdentityProofV2) {
            return (IdentityProofV2)o;
        } else {
            return o != null ? new IdentityProofV2(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public AlgorithmIdentifier getProofAlgID() {
        return this.proofAlgID;
    }

    public AlgorithmIdentifier getMacAlgId() {
        return this.macAlgId;
    }

    public byte[] getWitness() {
        return Arrays.clone(this.witness);
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.proofAlgID);
        v.add(this.macAlgId);
        v.add(new DEROctetString(this.getWitness()));
        return new DERSequence(v);
    }
}