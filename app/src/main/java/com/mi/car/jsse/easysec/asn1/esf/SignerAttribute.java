package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.Attribute;
import com.mi.car.jsse.easysec.asn1.x509.AttributeCertificate;
import java.util.Enumeration;

public class SignerAttribute extends ASN1Object {
    private Object[] values;

    public static SignerAttribute getInstance(Object o) {
        if (o instanceof SignerAttribute) {
            return (SignerAttribute) o;
        }
        if (o != null) {
            return new SignerAttribute(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private SignerAttribute(ASN1Sequence seq) {
        int index = 0;
        this.values = new Object[seq.size()];
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(e.nextElement());
            if (taggedObject.getTagNo() == 0) {
                ASN1Sequence attrs = ASN1Sequence.getInstance(taggedObject, true);
                Attribute[] attributes = new Attribute[attrs.size()];
                for (int i = 0; i != attributes.length; i++) {
                    attributes[i] = Attribute.getInstance(attrs.getObjectAt(i));
                }
                this.values[index] = attributes;
            } else if (taggedObject.getTagNo() == 1) {
                this.values[index] = AttributeCertificate.getInstance(ASN1Sequence.getInstance(taggedObject, true));
            } else {
                throw new IllegalArgumentException("illegal tag: " + taggedObject.getTagNo());
            }
            index++;
        }
    }

    public SignerAttribute(Attribute[] claimedAttributes) {
        this.values = new Object[1];
        this.values[0] = claimedAttributes;
    }

    public SignerAttribute(AttributeCertificate certifiedAttributes) {
        this.values = new Object[1];
        this.values[0] = certifiedAttributes;
    }

    public Object[] getValues() {
        Object[] rv = new Object[this.values.length];
        System.arraycopy(this.values, 0, rv, 0, rv.length);
        return rv;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(this.values.length);
        for (int i = 0; i != this.values.length; i++) {
            if (this.values[i] instanceof Attribute[]) {
                v.add(new DERTaggedObject(0, new DERSequence((Attribute[]) this.values[i])));
            } else {
                v.add(new DERTaggedObject(1, (AttributeCertificate) this.values[i]));
            }
        }
        return new DERSequence(v);
    }
}
