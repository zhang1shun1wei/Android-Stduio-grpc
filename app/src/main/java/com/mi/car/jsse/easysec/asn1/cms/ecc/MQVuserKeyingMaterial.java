//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms.ecc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.cms.OriginatorPublicKey;

public class MQVuserKeyingMaterial extends ASN1Object {
    private OriginatorPublicKey ephemeralPublicKey;
    private ASN1OctetString addedukm;

    public MQVuserKeyingMaterial(OriginatorPublicKey ephemeralPublicKey, ASN1OctetString addedukm) {
        if (ephemeralPublicKey == null) {
            throw new IllegalArgumentException("Ephemeral public key cannot be null");
        } else {
            this.ephemeralPublicKey = ephemeralPublicKey;
            this.addedukm = addedukm;
        }
    }

    private MQVuserKeyingMaterial(ASN1Sequence seq) {
        if (seq.size() != 1 && seq.size() != 2) {
            throw new IllegalArgumentException("Sequence has incorrect number of elements");
        } else {
            this.ephemeralPublicKey = OriginatorPublicKey.getInstance(seq.getObjectAt(0));
            if (seq.size() > 1) {
                this.addedukm = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true);
            }

        }
    }

    public static MQVuserKeyingMaterial getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static MQVuserKeyingMaterial getInstance(Object obj) {
        if (obj instanceof MQVuserKeyingMaterial) {
            return (MQVuserKeyingMaterial)obj;
        } else {
            return obj != null ? new MQVuserKeyingMaterial(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public OriginatorPublicKey getEphemeralPublicKey() {
        return this.ephemeralPublicKey;
    }

    public ASN1OctetString getAddedukm() {
        return this.addedukm;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.ephemeralPublicKey);
        if (this.addedukm != null) {
            v.add(new DERTaggedObject(true, 0, this.addedukm));
        }

        return new DERSequence(v);
    }
}
