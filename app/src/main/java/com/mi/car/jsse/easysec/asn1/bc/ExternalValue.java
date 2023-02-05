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
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;

public class ExternalValue extends ASN1Object {
    private final GeneralName location;
    private final AlgorithmIdentifier hashAlg;
    private final ASN1BitString hashVal;

    public ExternalValue(GeneralName location, AlgorithmIdentifier hashAlg, byte[] hashVal) {
        this.location = location;
        this.hashAlg = hashAlg;
        this.hashVal = new DERBitString(hashVal);
    }

    private ExternalValue(ASN1Sequence seq) {
        if (seq.size() == 3) {
            this.location = GeneralName.getInstance(seq.getObjectAt(0));
            this.hashAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            this.hashVal = ASN1BitString.getInstance(seq.getObjectAt(2));
        } else {
            throw new IllegalArgumentException("unknown sequence");
        }
    }

    public static ExternalValue getInstance(Object o) {
        if (o instanceof ExternalValue) {
            return (ExternalValue)o;
        } else {
            return o != null ? new ExternalValue(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public GeneralName getLocation() {
        return this.location;
    }

    public AlgorithmIdentifier getHashAlg() {
        return this.hashAlg;
    }

    public ASN1BitString getHashVal() {
        return this.hashVal;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.location);
        v.add(this.hashAlg);
        v.add(this.hashVal);
        return new DERSequence(v);
    }
}