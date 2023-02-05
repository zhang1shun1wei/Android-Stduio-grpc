package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.io.IOException;
import java.util.Enumeration;

public class SubjectPublicKeyInfo extends ASN1Object {
    private AlgorithmIdentifier algId;
    private ASN1BitString keyData;

    public static SubjectPublicKeyInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SubjectPublicKeyInfo getInstance(Object obj) {
        if (obj instanceof SubjectPublicKeyInfo) {
            return (SubjectPublicKeyInfo) obj;
        }
        if (obj != null) {
            return new SubjectPublicKeyInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public SubjectPublicKeyInfo(AlgorithmIdentifier algId2, ASN1Encodable publicKey) throws IOException {
        this.keyData = new DERBitString(publicKey);
        this.algId = algId2;
    }

    public SubjectPublicKeyInfo(AlgorithmIdentifier algId2, byte[] publicKey) {
        this.keyData = new DERBitString(publicKey);
        this.algId = algId2;
    }

    public SubjectPublicKeyInfo(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        this.algId = AlgorithmIdentifier.getInstance(e.nextElement());
        this.keyData = DERBitString.getInstance(e.nextElement());
    }

    public AlgorithmIdentifier getAlgorithm() {
        return this.algId;
    }

    public AlgorithmIdentifier getAlgorithmId() {
        return this.algId;
    }

    public ASN1Primitive parsePublicKey() throws IOException {
        return ASN1Primitive.fromByteArray(this.keyData.getOctets());
    }

    public ASN1Primitive getPublicKey() throws IOException {
        return ASN1Primitive.fromByteArray(this.keyData.getOctets());
    }

    public ASN1BitString getPublicKeyData() {
        return this.keyData;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.algId);
        v.add(this.keyData);
        return new DERSequence(v);
    }
}
