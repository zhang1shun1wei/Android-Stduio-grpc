package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;
import java.util.Enumeration;

public class PartialHashtree extends ASN1Object {
    private final ASN1Sequence values;

    public static PartialHashtree getInstance(Object obj) {
        if (obj instanceof PartialHashtree) {
            return (PartialHashtree) obj;
        }
        if (obj != null) {
            return new PartialHashtree(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private PartialHashtree(ASN1Sequence values2) {
        for (int i = 0; i != values2.size(); i++) {
            if (!(values2.getObjectAt(i) instanceof DEROctetString)) {
                throw new IllegalArgumentException("unknown object in constructor: " + values2.getObjectAt(i).getClass().getName());
            }
        }
        this.values = values2;
    }

    public PartialHashtree(byte[] values2) {
        this(new byte[][]{values2});
    }

    public PartialHashtree(byte[][] values2) {
        ASN1EncodableVector v = new ASN1EncodableVector(values2.length);
        for (int i = 0; i != values2.length; i++) {
            v.add(new DEROctetString(Arrays.clone(values2[i])));
        }
        this.values = new DERSequence(v);
    }

    public int getValueCount() {
        return this.values.size();
    }

    public byte[][] getValues() {
        byte[][] rv = new byte[this.values.size()][];
        for (int i = 0; i != rv.length; i++) {
            rv[i] = Arrays.clone(ASN1OctetString.getInstance(this.values.getObjectAt(i)).getOctets());
        }
        return rv;
    }

    public boolean containsHash(byte[] hash) {
        Enumeration hashes = this.values.getObjects();
        while (hashes.hasMoreElements()) {
            if (Arrays.constantTimeAreEqual(hash, ASN1OctetString.getInstance(hashes.nextElement()).getOctets())) {
                return true;
            }
        }
        return false;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.values;
    }
}
