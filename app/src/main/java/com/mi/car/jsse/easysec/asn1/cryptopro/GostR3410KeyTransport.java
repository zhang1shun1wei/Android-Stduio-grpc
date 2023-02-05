package com.mi.car.jsse.easysec.asn1.cryptopro;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class GostR3410KeyTransport extends ASN1Object {
    private final Gost2814789EncryptedKey sessionEncryptedKey;
    private final GostR3410TransportParameters transportParameters;

    private GostR3410KeyTransport(ASN1Sequence seq) {
        this.sessionEncryptedKey = Gost2814789EncryptedKey.getInstance(seq.getObjectAt(0));
        this.transportParameters = GostR3410TransportParameters.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(1)), false);
    }

    public GostR3410KeyTransport(Gost2814789EncryptedKey sessionEncryptedKey2, GostR3410TransportParameters transportParameters2) {
        this.sessionEncryptedKey = sessionEncryptedKey2;
        this.transportParameters = transportParameters2;
    }

    public static GostR3410KeyTransport getInstance(Object obj) {
        if (obj instanceof GostR3410KeyTransport) {
            return (GostR3410KeyTransport) obj;
        }
        if (obj != null) {
            return new GostR3410KeyTransport(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public Gost2814789EncryptedKey getSessionEncryptedKey() {
        return this.sessionEncryptedKey;
    }

    public GostR3410TransportParameters getTransportParameters() {
        return this.transportParameters;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.sessionEncryptedKey);
        if (this.transportParameters != null) {
            v.add(new DERTaggedObject(false, 0, (ASN1Encodable) this.transportParameters));
        }
        return new DERSequence(v);
    }
}
