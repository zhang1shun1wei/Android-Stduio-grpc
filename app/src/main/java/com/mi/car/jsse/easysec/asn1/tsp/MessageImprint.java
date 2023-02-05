package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Arrays;

public class MessageImprint extends ASN1Object {
    AlgorithmIdentifier hashAlgorithm;
    byte[] hashedMessage;

    public static MessageImprint getInstance(Object o) {
        if (o instanceof MessageImprint) {
            return (MessageImprint) o;
        }
        if (o != null) {
            return new MessageImprint(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private MessageImprint(ASN1Sequence seq) {
        if (seq.size() == 2) {
            this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
            this.hashedMessage = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
            return;
        }
        throw new IllegalArgumentException("sequence has wrong number of elements");
    }

    public MessageImprint(AlgorithmIdentifier hashAlgorithm2, byte[] hashedMessage2) {
        this.hashAlgorithm = hashAlgorithm2;
        this.hashedMessage = Arrays.clone(hashedMessage2);
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public byte[] getHashedMessage() {
        return Arrays.clone(this.hashedMessage);
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.hashAlgorithm);
        v.add(new DEROctetString(this.hashedMessage));
        return new DERSequence(v);
    }
}
