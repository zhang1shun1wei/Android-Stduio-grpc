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

public class ECPrivateKey extends ASN1Object {
    private ASN1Sequence seq;

    private ECPrivateKey(ASN1Sequence seq2) {
        this.seq = seq2;
    }

    public static ECPrivateKey getInstance(Object obj) {
        if (obj instanceof ECPrivateKey) {
            return (ECPrivateKey) obj;
        }
        if (obj != null) {
            return new ECPrivateKey(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ECPrivateKey(BigInteger key) {
        this(key.bitLength(), key);
    }

    public ECPrivateKey(int orderBitLength, BigInteger key) {
        byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(new ASN1Integer(1));
        v.add(new DEROctetString(bytes));
        this.seq = new DERSequence(v);
    }

    public ECPrivateKey(BigInteger key, ASN1Encodable parameters) {
        this(key, (ASN1BitString) null, parameters);
    }

    public ECPrivateKey(BigInteger key, ASN1BitString publicKey, ASN1Encodable parameters) {
        this(key.bitLength(), key, publicKey, parameters);
    }

    public ECPrivateKey(int orderBitLength, BigInteger key, ASN1Encodable parameters) {
        this(orderBitLength, key, null, parameters);
    }

    public ECPrivateKey(int orderBitLength, BigInteger key, ASN1BitString publicKey, ASN1Encodable parameters) {
        byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(new ASN1Integer(1));
        v.add(new DEROctetString(bytes));
        if (parameters != null) {
            v.add(new DERTaggedObject(true, 0, parameters));
        }
        if (publicKey != null) {
            v.add(new DERTaggedObject(true, 1, (ASN1Encodable) publicKey));
        }
        this.seq = new DERSequence(v);
    }

    public BigInteger getKey() {
        return new BigInteger(1, ((ASN1OctetString) this.seq.getObjectAt(1)).getOctets());
    }

    public ASN1BitString getPublicKey() {
        return (ASN1BitString) getObjectInTag(1, 3);
    }

    public ASN1Primitive getParameters() {
        return getParametersObject().toASN1Primitive();
    }

    public ASN1Object getParametersObject() {
        return getObjectInTag(0, -1);
    }

    private ASN1Object getObjectInTag(int tagNo, int baseTagNo) {
        Enumeration e = this.seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1Encodable obj = (ASN1Encodable) e.nextElement();
            if (obj instanceof ASN1TaggedObject) {
                ASN1TaggedObject tag = (ASN1TaggedObject) obj;
                if (tag.hasContextTag(tagNo)) {
                    if (baseTagNo < 0) {
                        return tag.getExplicitBaseObject().toASN1Primitive();
                    }
                    return tag.getBaseUniversal(true, baseTagNo);
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
