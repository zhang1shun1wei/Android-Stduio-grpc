//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class Challenge extends ASN1Object {
    private AlgorithmIdentifier owf;
    private final ASN1OctetString witness;
    private final ASN1OctetString challenge;

    private Challenge(ASN1Sequence seq) {
        int index = 0;
        if (seq.size() == 3) {
            this.owf = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
        }

        this.witness = ASN1OctetString.getInstance(seq.getObjectAt(index++));
        this.challenge = ASN1OctetString.getInstance(seq.getObjectAt(index));
    }

    public Challenge(byte[] witness, byte[] challenge) {
        this((AlgorithmIdentifier)null, witness, challenge);
    }

    public Challenge(AlgorithmIdentifier owf, byte[] witness, byte[] challenge) {
        this.owf = owf;
        this.witness = new DEROctetString(witness);
        this.challenge = new DEROctetString(challenge);
    }

    public static Challenge getInstance(Object o) {
        if (o instanceof Challenge) {
            return (Challenge)o;
        } else {
            return o != null ? new Challenge(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public AlgorithmIdentifier getOwf() {
        return this.owf;
    }

    public byte[] getWitness() {
        return this.witness.getOctets();
    }

    public byte[] getChallenge() {
        return this.challenge.getOctets();
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        this.addOptional(v, this.owf);
        v.add(this.witness);
        v.add(this.challenge);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, ASN1Encodable obj) {
        if (obj != null) {
            v.add(obj);
        }

    }
}