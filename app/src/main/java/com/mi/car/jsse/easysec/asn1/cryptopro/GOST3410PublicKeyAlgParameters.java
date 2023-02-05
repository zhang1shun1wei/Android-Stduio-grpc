package com.mi.car.jsse.easysec.asn1.cryptopro;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class GOST3410PublicKeyAlgParameters extends ASN1Object {
    private ASN1ObjectIdentifier digestParamSet;
    private ASN1ObjectIdentifier encryptionParamSet;
    private ASN1ObjectIdentifier publicKeyParamSet;

    public static GOST3410PublicKeyAlgParameters getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GOST3410PublicKeyAlgParameters getInstance(Object obj) {
        if (obj instanceof GOST3410PublicKeyAlgParameters) {
            return (GOST3410PublicKeyAlgParameters) obj;
        }
        if (obj != null) {
            return new GOST3410PublicKeyAlgParameters(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public GOST3410PublicKeyAlgParameters(ASN1ObjectIdentifier publicKeyParamSet2, ASN1ObjectIdentifier digestParamSet2) {
        this.publicKeyParamSet = publicKeyParamSet2;
        this.digestParamSet = digestParamSet2;
        this.encryptionParamSet = null;
    }

    public GOST3410PublicKeyAlgParameters(ASN1ObjectIdentifier publicKeyParamSet2, ASN1ObjectIdentifier digestParamSet2, ASN1ObjectIdentifier encryptionParamSet2) {
        this.publicKeyParamSet = publicKeyParamSet2;
        this.digestParamSet = digestParamSet2;
        this.encryptionParamSet = encryptionParamSet2;
    }

    private GOST3410PublicKeyAlgParameters(ASN1Sequence seq) {
        this.publicKeyParamSet = (ASN1ObjectIdentifier) seq.getObjectAt(0);
        this.digestParamSet = (ASN1ObjectIdentifier) seq.getObjectAt(1);
        if (seq.size() > 2) {
            this.encryptionParamSet = (ASN1ObjectIdentifier) seq.getObjectAt(2);
        }
    }

    public ASN1ObjectIdentifier getPublicKeyParamSet() {
        return this.publicKeyParamSet;
    }

    public ASN1ObjectIdentifier getDigestParamSet() {
        return this.digestParamSet;
    }

    public ASN1ObjectIdentifier getEncryptionParamSet() {
        return this.encryptionParamSet;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.publicKeyParamSet);
        v.add(this.digestParamSet);
        if (this.encryptionParamSet != null) {
            v.add(this.encryptionParamSet);
        }
        return new DERSequence(v);
    }
}
