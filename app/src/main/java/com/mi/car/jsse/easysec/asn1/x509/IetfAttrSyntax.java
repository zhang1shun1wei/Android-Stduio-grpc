package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.util.Enumeration;
import java.util.Vector;

public class IetfAttrSyntax extends ASN1Object {
    public static final int VALUE_OCTETS = 1;
    public static final int VALUE_OID = 2;
    public static final int VALUE_UTF8 = 3;
    GeneralNames policyAuthority = null;
    int valueChoice = -1;
    Vector values = new Vector();

    public static IetfAttrSyntax getInstance(Object obj) {
        if (obj instanceof IetfAttrSyntax) {
            return (IetfAttrSyntax) obj;
        }
        if (obj != null) {
            return new IetfAttrSyntax(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private IetfAttrSyntax(ASN1Sequence seq) {
        int type;
        int i = 0;
        if (seq.getObjectAt(0) instanceof ASN1TaggedObject) {
            this.policyAuthority = GeneralNames.getInstance((ASN1TaggedObject) seq.getObjectAt(0), false);
            i = 0 + 1;
        } else if (seq.size() == 2) {
            this.policyAuthority = GeneralNames.getInstance(seq.getObjectAt(0));
            i = 0 + 1;
        }
        if (!(seq.getObjectAt(i) instanceof ASN1Sequence)) {
            throw new IllegalArgumentException("Non-IetfAttrSyntax encoding");
        }
        Enumeration e = ((ASN1Sequence) seq.getObjectAt(i)).getObjects();
        while (e.hasMoreElements()) {
            ASN1Primitive obj = (ASN1Primitive) e.nextElement();
            if (obj instanceof ASN1ObjectIdentifier) {
                type = 2;
            } else if (obj instanceof ASN1UTF8String) {
                type = 3;
            } else if (obj instanceof DEROctetString) {
                type = 1;
            } else {
                throw new IllegalArgumentException("Bad value type encoding IetfAttrSyntax");
            }
            if (this.valueChoice < 0) {
                this.valueChoice = type;
            }
            if (type != this.valueChoice) {
                throw new IllegalArgumentException("Mix of value types in IetfAttrSyntax");
            }
            this.values.addElement(obj);
        }
    }

    public GeneralNames getPolicyAuthority() {
        return this.policyAuthority;
    }

    public int getValueType() {
        return this.valueChoice;
    }

    public Object[] getValues() {
        Object[] objArr;
        if (getValueType() == 1) {
            objArr = new ASN1OctetString[this.values.size()];
            for (int i = 0; i != objArr.length; i++) {
                objArr[i] = (ASN1OctetString) this.values.elementAt(i);
            }
        } else if (getValueType() == 2) {
            objArr = new ASN1ObjectIdentifier[this.values.size()];
            for (int i2 = 0; i2 != objArr.length; i2++) {
                objArr[i2] = (ASN1ObjectIdentifier) this.values.elementAt(i2);
            }
        } else {
            objArr = new ASN1UTF8String[this.values.size()];
            for (int i3 = 0; i3 != objArr.length; i3++) {
                objArr[i3] = (ASN1UTF8String) this.values.elementAt(i3);
            }
        }
        return objArr;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this.policyAuthority != null) {
            v.add(new DERTaggedObject(0, this.policyAuthority));
        }
        ASN1EncodableVector v2 = new ASN1EncodableVector(this.values.size());
        Enumeration i = this.values.elements();
        while (i.hasMoreElements()) {
            v2.add((ASN1Encodable) i.nextElement());
        }
        v.add(new DERSequence(v2));
        return new DERSequence(v);
    }
}
