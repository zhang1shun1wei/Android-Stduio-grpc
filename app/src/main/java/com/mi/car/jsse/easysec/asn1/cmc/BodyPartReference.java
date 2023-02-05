//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import java.io.IOException;

public class BodyPartReference extends ASN1Object implements ASN1Choice {
    private final BodyPartID bodyPartID;
    private final BodyPartPath bodyPartPath;

    public BodyPartReference(BodyPartID bodyPartID) {
        this.bodyPartID = bodyPartID;
        this.bodyPartPath = null;
    }

    public BodyPartReference(BodyPartPath bodyPartPath) {
        this.bodyPartID = null;
        this.bodyPartPath = bodyPartPath;
    }

    public static BodyPartReference getInstance(Object obj) {
        if (obj instanceof BodyPartReference) {
            return (BodyPartReference)obj;
        } else if (obj != null) {
            if (obj instanceof ASN1Encodable) {
                ASN1Encodable asn1Prim = ((ASN1Encodable)obj).toASN1Primitive();
                if (asn1Prim instanceof ASN1Integer) {
                    return new BodyPartReference(BodyPartID.getInstance(asn1Prim));
                }

                if (asn1Prim instanceof ASN1Sequence) {
                    return new BodyPartReference(BodyPartPath.getInstance(asn1Prim));
                }
            }

            if (obj instanceof byte[]) {
                try {
                    return getInstance(ASN1Primitive.fromByteArray((byte[])((byte[])obj)));
                } catch (IOException var2) {
                    throw new IllegalArgumentException("unknown encoding in getInstance()");
                }
            } else {
                throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
            }
        } else {
            return null;
        }
    }

    public boolean isBodyPartID() {
        return this.bodyPartID != null;
    }

    public BodyPartID getBodyPartID() {
        return this.bodyPartID;
    }

    public BodyPartPath getBodyPartPath() {
        return this.bodyPartPath;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.bodyPartID != null ? this.bodyPartID.toASN1Primitive() : this.bodyPartPath.toASN1Primitive();
    }
}