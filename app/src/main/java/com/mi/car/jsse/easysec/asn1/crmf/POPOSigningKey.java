package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class POPOSigningKey extends ASN1Object {
    private POPOSigningKeyInput poposkInput;
    private AlgorithmIdentifier algorithmIdentifier;
    private ASN1BitString signature;

    private POPOSigningKey(ASN1Sequence seq) {
        int index = 0;
        if (seq.getObjectAt(index) instanceof ASN1TaggedObject) {
            ASN1TaggedObject tagObj = (ASN1TaggedObject)seq.getObjectAt(index++);
            if (tagObj.getTagNo() != 0) {
                throw new IllegalArgumentException("Unknown POPOSigningKeyInput tag: " + tagObj.getTagNo());
            }

            this.poposkInput = POPOSigningKeyInput.getInstance(tagObj.getObject());
        }

        this.algorithmIdentifier = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
        this.signature = ASN1BitString.getInstance(seq.getObjectAt(index));
    }

    public static POPOSigningKey getInstance(Object o) {
        if (o instanceof POPOSigningKey) {
            return (POPOSigningKey)o;
        } else {
            return o != null ? new POPOSigningKey(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public static POPOSigningKey getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public POPOSigningKey(POPOSigningKeyInput poposkIn, AlgorithmIdentifier aid, ASN1BitString signature) {
        this.poposkInput = poposkIn;
        this.algorithmIdentifier = aid;
        this.signature = signature;
    }

    public POPOSigningKeyInput getPoposkInput() {
        return this.poposkInput;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return this.algorithmIdentifier;
    }

    public ASN1BitString getSignature() {
        return this.signature;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        if (this.poposkInput != null) {
            v.add(new DERTaggedObject(false, 0, this.poposkInput));
        }

        v.add(this.algorithmIdentifier);
        v.add(this.signature);
        return new DERSequence(v);
    }
}
