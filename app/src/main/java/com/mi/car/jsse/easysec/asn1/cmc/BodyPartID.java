//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import java.math.BigInteger;

public class BodyPartID extends ASN1Object {
    public static final long bodyIdMax = 4294967295L;
    private final long id;

    public BodyPartID(long id) {
        if (id >= 0L && id <= 4294967295L) {
            this.id = id;
        } else {
            throw new IllegalArgumentException("id out of range");
        }
    }

    private static long convert(BigInteger value) {
        if (value.bitLength() > 32) {
            throw new IllegalArgumentException("id out of range");
        } else {
            return value.longValue();
        }
    }

    private BodyPartID(ASN1Integer id) {
        this(convert(id.getValue()));
    }

    public static BodyPartID getInstance(Object o) {
        if (o instanceof BodyPartID) {
            return (BodyPartID)o;
        } else {
            return o != null ? new BodyPartID(ASN1Integer.getInstance(o)) : null;
        }
    }

    public long getID() {
        return this.id;
    }

    public ASN1Primitive toASN1Primitive() {
        return new ASN1Integer(this.id);
    }
}