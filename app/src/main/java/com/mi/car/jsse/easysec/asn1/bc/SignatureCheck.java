//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.bc;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.Certificate;
import com.mi.car.jsse.easysec.util.Arrays;

public class SignatureCheck extends ASN1Object {
    private final AlgorithmIdentifier signatureAlgorithm;
    private final ASN1Sequence certificates;
    private final ASN1BitString signatureValue;

    public SignatureCheck(AlgorithmIdentifier signatureAlgorithm, byte[] signature) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.certificates = null;
        this.signatureValue = new DERBitString(Arrays.clone(signature));
    }

    public SignatureCheck(AlgorithmIdentifier signatureAlgorithm, Certificate[] certificates, byte[] signature) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.certificates = new DERSequence(certificates);
        this.signatureValue = new DERBitString(Arrays.clone(signature));
    }

    private SignatureCheck(ASN1Sequence seq) {
        this.signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        int index = 1;
        if (seq.getObjectAt(1) instanceof ASN1TaggedObject) {
            this.certificates = ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(index++)).getObject());
        } else {
            this.certificates = null;
        }

        this.signatureValue = DERBitString.getInstance(seq.getObjectAt(index));
    }

    public static SignatureCheck getInstance(Object o) {
        if (o instanceof SignatureCheck) {
            return (SignatureCheck)o;
        } else {
            return o != null ? new SignatureCheck(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1BitString getSignature() {
        return new DERBitString(this.signatureValue.getBytes(), this.signatureValue.getPadBits());
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public Certificate[] getCertificates() {
        if (this.certificates == null) {
            return null;
        } else {
            Certificate[] certs = new Certificate[this.certificates.size()];

            for(int i = 0; i != certs.length; ++i) {
                certs[i] = Certificate.getInstance(this.certificates.getObjectAt(i));
            }

            return certs;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.signatureAlgorithm);
        if (this.certificates != null) {
            v.add(new DERTaggedObject(0, this.certificates));
        }

        v.add(this.signatureValue);
        return new DERSequence(v);
    }
}