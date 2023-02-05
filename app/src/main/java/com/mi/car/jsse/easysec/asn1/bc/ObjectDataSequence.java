//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.bc;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Iterable;
import java.util.Iterator;

public class ObjectDataSequence extends ASN1Object implements Iterable<ASN1Encodable> {
    private final ASN1Encodable[] dataSequence;

    public ObjectDataSequence(ObjectData[] dataSequence) {
        this.dataSequence = new ASN1Encodable[dataSequence.length];
        System.arraycopy(dataSequence, 0, this.dataSequence, 0, dataSequence.length);
    }

    private ObjectDataSequence(ASN1Sequence seq) {
        this.dataSequence = new ASN1Encodable[seq.size()];

        for(int i = 0; i != this.dataSequence.length; ++i) {
            this.dataSequence[i] = ObjectData.getInstance(seq.getObjectAt(i));
        }

    }

    public static ObjectDataSequence getInstance(Object obj) {
        if (obj instanceof ObjectDataSequence) {
            return (ObjectDataSequence)obj;
        } else {
            return obj != null ? new ObjectDataSequence(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(this.dataSequence);
    }

    public Iterator<ASN1Encodable> iterator() {
        return new com.mi.car.jsse.easysec.util.Arrays.Iterator(this.dataSequence);
    }
}