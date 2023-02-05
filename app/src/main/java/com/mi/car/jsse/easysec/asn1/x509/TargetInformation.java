package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;

public class TargetInformation extends ASN1Object {
    private ASN1Sequence targets;

    public static TargetInformation getInstance(Object obj) {
        if (obj instanceof TargetInformation) {
            return (TargetInformation) obj;
        }
        if (obj != null) {
            return new TargetInformation(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private TargetInformation(ASN1Sequence seq) {
        this.targets = seq;
    }

    public Targets[] getTargetsObjects() {
        Targets[] copy = new Targets[this.targets.size()];
        int count = 0;
        Enumeration e = this.targets.getObjects();
        while (e.hasMoreElements()) {
            copy[count] = Targets.getInstance(e.nextElement());
            count++;
        }
        return copy;
    }

    public TargetInformation(Targets targets2) {
        this.targets = new DERSequence(targets2);
    }

    public TargetInformation(Target[] targets2) {
        this(new Targets(targets2));
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.targets;
    }
}
