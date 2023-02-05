package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;

public class Targets extends ASN1Object {
    private ASN1Sequence targets;

    public static Targets getInstance(Object obj) {
        if (obj instanceof Targets) {
            return (Targets) obj;
        }
        if (obj != null) {
            return new Targets(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private Targets(ASN1Sequence targets2) {
        this.targets = targets2;
    }

    public Targets(Target[] targets2) {
        this.targets = new DERSequence(targets2);
    }

    public Target[] getTargets() {
        Target[] targs = new Target[this.targets.size()];
        int count = 0;
        Enumeration e = this.targets.getObjects();
        while (e.hasMoreElements()) {
            targs[count] = Target.getInstance(e.nextElement());
            count++;
        }
        return targs;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.targets;
    }
}
