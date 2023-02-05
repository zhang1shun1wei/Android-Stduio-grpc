package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;

public class EncKeyWithID extends ASN1Object {
    private final ASN1Encodable identifier;
    private final PrivateKeyInfo privKeyInfo;

    public static EncKeyWithID getInstance(Object o) {
        if (o instanceof EncKeyWithID) {
            return (EncKeyWithID) o;
        }
        if (o != null) {
            return new EncKeyWithID(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private EncKeyWithID(ASN1Sequence seq) {
        this.privKeyInfo = PrivateKeyInfo.getInstance(seq.getObjectAt(0));
        if (seq.size() <= 1) {
            this.identifier = null;
        } else if (!(seq.getObjectAt(1) instanceof ASN1UTF8String)) {
            this.identifier = GeneralName.getInstance(seq.getObjectAt(1));
        } else {
            this.identifier = seq.getObjectAt(1);
        }
    }

    public EncKeyWithID(PrivateKeyInfo privKeyInfo2) {
        this.privKeyInfo = privKeyInfo2;
        this.identifier = null;
    }

    public EncKeyWithID(PrivateKeyInfo privKeyInfo2, ASN1UTF8String str) {
        this.privKeyInfo = privKeyInfo2;
        this.identifier = str;
    }

    public EncKeyWithID(PrivateKeyInfo privKeyInfo2, GeneralName generalName) {
        this.privKeyInfo = privKeyInfo2;
        this.identifier = generalName;
    }

    public PrivateKeyInfo getPrivateKey() {
        return this.privKeyInfo;
    }

    public boolean hasIdentifier() {
        return this.identifier != null;
    }

    public boolean isIdentifierUTF8String() {
        return this.identifier instanceof ASN1UTF8String;
    }

    public ASN1Encodable getIdentifier() {
        return this.identifier;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.privKeyInfo);
        if (this.identifier != null) {
            v.add(this.identifier);
        }
        return new DERSequence(v);
    }
}
