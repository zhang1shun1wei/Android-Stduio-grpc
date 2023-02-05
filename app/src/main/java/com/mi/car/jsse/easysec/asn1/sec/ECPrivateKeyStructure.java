package com.mi.car.jsse.easysec.asn1.sec;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.util.Enumeration;

public class ECPrivateKeyStructure extends ASN1Object {
    private ASN1Sequence seq;

    public ECPrivateKeyStructure(ASN1Sequence seq2) {
        this.seq = seq2;
    }

    public ECPrivateKeyStructure(BigInteger key) {
        byte[] bytes = BigIntegers.asUnsignedByteArray(key);
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(new ASN1Integer(1));
        v.add(new DEROctetString(bytes));
        this.seq = new DERSequence(v);
    }

    public ECPrivateKeyStructure(BigInteger key, ASN1Encodable parameters) {
        this(key, null, parameters);
    }

    public ECPrivateKeyStructure(BigInteger key, ASN1BitString publicKey, ASN1Encodable parameters) {
        byte[] bytes = BigIntegers.asUnsignedByteArray(key);
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(new ASN1Integer(1));
        v.add(new DEROctetString(bytes));
        if (parameters != null) {
            v.add(new DERTaggedObject(true, 0, parameters));
        }
        if (publicKey != null) {
            v.add(new DERTaggedObject(true, 1, (ASN1Encodable) publicKey));
            v.add(new DERTaggedObject(true, 1, (ASN1Encodable) publicKey));
        }
        this.seq = new DERSequence(v);
    }

    public BigInteger getKey() {
        return new BigInteger(1, ((ASN1OctetString) this.seq.getObjectAt(1)).getOctets());
    }

    public ASN1BitString getPublicKey() {
        return (ASN1BitString) getObjectInTag(1);
    }

    public ASN1Primitive getParameters() {
        return getObjectInTag(0);
    }

    private ASN1Primitive getObjectInTag(int tagNo) {
        Enumeration e = this.seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1Encodable obj = (ASN1Encodable) e.nextElement();
            if (obj instanceof ASN1TaggedObject) {
                ASN1TaggedObject tag = (ASN1TaggedObject) obj;
                if (tag.getTagNo() == tagNo) {
                    return tag.getObject().toASN1Primitive();
                }
            }
        }
        return null;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.seq;
    }
}
