package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Strings;

public class GeneralNames extends ASN1Object {
    private final GeneralName[] names;

    private static GeneralName[] copy(GeneralName[] names2) {
        GeneralName[] result = new GeneralName[names2.length];
        System.arraycopy(names2, 0, result, 0, names2.length);
        return result;
    }

    public static GeneralNames getInstance(Object obj) {
        if (obj instanceof GeneralNames) {
            return (GeneralNames) obj;
        }
        if (obj != null) {
            return new GeneralNames(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static GeneralNames getInstance(ASN1TaggedObject obj, boolean explicit) {
        return new GeneralNames(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GeneralNames fromExtensions(Extensions extensions, ASN1ObjectIdentifier extOID) {
        return getInstance(Extensions.getExtensionParsedValue(extensions, extOID));
    }

    public GeneralNames(GeneralName name) {
        this.names = new GeneralName[]{name};
    }

    public GeneralNames(GeneralName[] names2) {
        this.names = copy(names2);
    }

    private GeneralNames(ASN1Sequence seq) {
        this.names = new GeneralName[seq.size()];
        for (int i = 0; i != seq.size(); i++) {
            this.names[i] = GeneralName.getInstance(seq.getObjectAt(i));
        }
    }

    public GeneralName[] getNames() {
        return copy(this.names);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(this.names);
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String sep = Strings.lineSeparator();
        buf.append("GeneralNames:");
        buf.append(sep);
        for (int i = 0; i != this.names.length; i++) {
            buf.append("    ");
            buf.append(this.names[i]);
            buf.append(sep);
        }
        return buf.toString();
    }
}
