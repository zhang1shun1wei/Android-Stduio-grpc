package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class EncryptedValue extends ASN1Object {
    private AlgorithmIdentifier intendedAlg;
    private AlgorithmIdentifier symmAlg;
    private ASN1BitString encSymmKey;
    private AlgorithmIdentifier keyAlg;
    private ASN1OctetString valueHint;
    private ASN1BitString encValue;

    private EncryptedValue(ASN1Sequence seq) {
        int index;
        for(index = 0; seq.getObjectAt(index) instanceof ASN1TaggedObject; ++index) {
            ASN1TaggedObject tObj = (ASN1TaggedObject)seq.getObjectAt(index);
            switch(tObj.getTagNo()) {
                case 0:
                    this.intendedAlg = AlgorithmIdentifier.getInstance(tObj, false);
                    break;
                case 1:
                    this.symmAlg = AlgorithmIdentifier.getInstance(tObj, false);
                    break;
                case 2:
                    this.encSymmKey = ASN1BitString.getInstance(tObj, false);
                    break;
                case 3:
                    this.keyAlg = AlgorithmIdentifier.getInstance(tObj, false);
                    break;
                case 4:
                    this.valueHint = ASN1OctetString.getInstance(tObj, false);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown tag encountered: " + tObj.getTagNo());
            }
        }

        this.encValue = ASN1BitString.getInstance(seq.getObjectAt(index));
    }

    public static EncryptedValue getInstance(Object o) {
        if (o instanceof EncryptedValue) {
            return (EncryptedValue)o;
        } else {
            return o != null ? new EncryptedValue(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public EncryptedValue(AlgorithmIdentifier intendedAlg, AlgorithmIdentifier symmAlg, ASN1BitString encSymmKey, AlgorithmIdentifier keyAlg, ASN1OctetString valueHint, ASN1BitString encValue) {
        if (encValue == null) {
            throw new IllegalArgumentException("'encValue' cannot be null");
        } else {
            this.intendedAlg = intendedAlg;
            this.symmAlg = symmAlg;
            this.encSymmKey = encSymmKey;
            this.keyAlg = keyAlg;
            this.valueHint = valueHint;
            this.encValue = encValue;
        }
    }

    public AlgorithmIdentifier getIntendedAlg() {
        return this.intendedAlg;
    }

    public AlgorithmIdentifier getSymmAlg() {
        return this.symmAlg;
    }

    public ASN1BitString getEncSymmKey() {
        return this.encSymmKey;
    }

    public AlgorithmIdentifier getKeyAlg() {
        return this.keyAlg;
    }

    public ASN1OctetString getValueHint() {
        return this.valueHint;
    }

    public ASN1BitString getEncValue() {
        return this.encValue;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(6);
        this.addOptional(v, 0, this.intendedAlg);
        this.addOptional(v, 1, this.symmAlg);
        this.addOptional(v, 2, this.encSymmKey);
        this.addOptional(v, 3, this.keyAlg);
        this.addOptional(v, 4, this.valueHint);
        v.add(this.encValue);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(false, tagNo, obj));
        }

    }
}
