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

public class PopLinkWitnessV2 extends ASN1Object {
    private final AlgorithmIdentifier keyGenAlgorithm;
    private final AlgorithmIdentifier macAlgorithm;
    private final byte[] witness;

    public PopLinkWitnessV2(AlgorithmIdentifier keyGenAlgorithm, AlgorithmIdentifier macAlgorithm, byte[] witness) {
        this.keyGenAlgorithm = keyGenAlgorithm;
        this.macAlgorithm = macAlgorithm;
        this.witness = Arrays.clone(witness);
    }

    private PopLinkWitnessV2(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.keyGenAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
            this.macAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            this.witness = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
        }
    }

    public static PopLinkWitnessV2 getInstance(Object o) {
        if (o instanceof PopLinkWitnessV2) {
            return (PopLinkWitnessV2)o;
        } else {
            return o != null ? new PopLinkWitnessV2(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public AlgorithmIdentifier getKeyGenAlgorithm() {
        return this.keyGenAlgorithm;
    }

    public AlgorithmIdentifier getMacAlgorithm() {
        return this.macAlgorithm;
    }

    public byte[] getWitness() {
        return Arrays.clone(this.witness);
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.keyGenAlgorithm);
        v.add(this.macAlgorithm);
        v.add(new DEROctetString(this.getWitness()));
        return new DERSequence(v);
    }
}