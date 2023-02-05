//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERUTF8String;
import java.util.Enumeration;

public class PKIFreeText extends ASN1Object {
    ASN1Sequence strings;

    private PKIFreeText(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();

        do {
            if (!e.hasMoreElements()) {
                this.strings = seq;
                return;
            }
        } while(e.nextElement() instanceof ASN1UTF8String);

        throw new IllegalArgumentException("attempt to insert non UTF8 STRING into PKIFreeText");
    }

    public PKIFreeText(ASN1UTF8String p) {
        this.strings = new DERSequence(p);
    }

    public PKIFreeText(String p) {
        this((ASN1UTF8String)(new DERUTF8String(p)));
    }

    public PKIFreeText(ASN1UTF8String[] strs) {
        this.strings = new DERSequence(strs);
    }

    public PKIFreeText(String[] strs) {
        ASN1EncodableVector v = new ASN1EncodableVector(strs.length);

        for(int i = 0; i < strs.length; ++i) {
            v.add(new DERUTF8String(strs[i]));
        }

        this.strings = new DERSequence(v);
    }

    public static PKIFreeText getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PKIFreeText getInstance(Object obj) {
        if (obj instanceof PKIFreeText) {
            return (PKIFreeText)obj;
        } else {
            return obj != null ? new PKIFreeText(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public int size() {
        return this.strings.size();
    }

    /** @deprecated */
    public DERUTF8String getStringAt(int i) {
        ASN1UTF8String stringAt = this.getStringAtUTF8(i);
        return null != stringAt && !(stringAt instanceof DERUTF8String) ? new DERUTF8String(stringAt.getString()) : (DERUTF8String)stringAt;
    }

    public ASN1UTF8String getStringAtUTF8(int i) {
        return (ASN1UTF8String)this.strings.getObjectAt(i);
    }

    public ASN1Primitive toASN1Primitive() {
        return this.strings;
    }
}
