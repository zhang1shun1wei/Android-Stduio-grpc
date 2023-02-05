//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.Extension;

public class ExtensionReq extends ASN1Object {
    private final Extension[] extensions;

    public static ExtensionReq getInstance(Object obj) {
        if (obj instanceof ExtensionReq) {
            return (ExtensionReq)obj;
        } else {
            return obj != null ? new ExtensionReq(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public static ExtensionReq getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ExtensionReq(Extension Extension) {
        this.extensions = new Extension[]{Extension};
    }

    public ExtensionReq(Extension[] extensions) {
        this.extensions = Utils.clone(extensions);
    }

    private ExtensionReq(ASN1Sequence seq) {
        this.extensions = new Extension[seq.size()];

        for(int i = 0; i != seq.size(); ++i) {
            this.extensions[i] = Extension.getInstance(seq.getObjectAt(i));
        }

    }

    public Extension[] getExtensions() {
        return Utils.clone(this.extensions);
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(this.extensions);
    }
}