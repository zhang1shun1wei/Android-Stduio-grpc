package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;
import java.util.Vector;

public class SubjectDirectoryAttributes extends ASN1Object {
    private Vector attributes = new Vector();

    public static SubjectDirectoryAttributes getInstance(Object obj) {
        if (obj instanceof SubjectDirectoryAttributes) {
            return (SubjectDirectoryAttributes) obj;
        }
        if (obj != null) {
            return new SubjectDirectoryAttributes(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private SubjectDirectoryAttributes(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            this.attributes.addElement(Attribute.getInstance(ASN1Sequence.getInstance(e.nextElement())));
        }
    }

    public SubjectDirectoryAttributes(Vector attributes2) {
        Enumeration e = attributes2.elements();
        while (e.hasMoreElements()) {
            this.attributes.addElement(e.nextElement());
        }
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(this.attributes.size());
        Enumeration e = this.attributes.elements();
        while (e.hasMoreElements()) {
            vec.add((Attribute) e.nextElement());
        }
        return new DERSequence(vec);
    }

    public Vector getAttributes() {
        return this.attributes;
    }
}
