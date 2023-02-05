//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.bc;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.io.IOException;

public class ObjectStoreIntegrityCheck extends ASN1Object implements ASN1Choice {
    public static final int PBKD_MAC_CHECK = 0;
    public static final int SIG_CHECK = 1;
    private final int type;
    private final ASN1Object integrityCheck;

    public ObjectStoreIntegrityCheck(PbkdMacIntegrityCheck macIntegrityCheck) {
        this((ASN1Encodable)macIntegrityCheck);
    }

    public ObjectStoreIntegrityCheck(SignatureCheck signatureCheck) {
        this((ASN1Encodable)(new DERTaggedObject(0, signatureCheck)));
    }

    private ObjectStoreIntegrityCheck(ASN1Encodable obj) {
        if (!(obj instanceof ASN1Sequence) && !(obj instanceof PbkdMacIntegrityCheck)) {
            if (!(obj instanceof ASN1TaggedObject)) {
                throw new IllegalArgumentException("Unknown check object in integrity check.");
            }

            this.type = 1;
            this.integrityCheck = SignatureCheck.getInstance(((ASN1TaggedObject)obj).getObject());
        } else {
            this.type = 0;
            this.integrityCheck = PbkdMacIntegrityCheck.getInstance(obj);
        }

    }

    public static ObjectStoreIntegrityCheck getInstance(Object o) {
        if (o instanceof ObjectStoreIntegrityCheck) {
            return (ObjectStoreIntegrityCheck)o;
        } else if (o instanceof byte[]) {
            try {
                return new ObjectStoreIntegrityCheck(ASN1Primitive.fromByteArray((byte[])((byte[])o)));
            } catch (IOException var2) {
                throw new IllegalArgumentException("Unable to parse integrity check details.");
            }
        } else {
            return o != null ? new ObjectStoreIntegrityCheck((ASN1Encodable)((ASN1Encodable)o)) : null;
        }
    }

    public int getType() {
        return this.type;
    }

    public ASN1Object getIntegrityCheck() {
        return this.integrityCheck;
    }

    public ASN1Primitive toASN1Primitive() {
        return (ASN1Primitive)(this.integrityCheck instanceof SignatureCheck ? new DERTaggedObject(0, this.integrityCheck) : this.integrityCheck.toASN1Primitive());
    }
}