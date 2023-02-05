package com.mi.car.jsse.easysec.asn1.cryptopro;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.util.Arrays;

public class GostR3410TransportParameters extends ASN1Object {
    private final ASN1ObjectIdentifier encryptionParamSet;
    private final SubjectPublicKeyInfo ephemeralPublicKey;
    private final byte[] ukm;

    public GostR3410TransportParameters(ASN1ObjectIdentifier encryptionParamSet2, SubjectPublicKeyInfo ephemeralPublicKey2, byte[] ukm2) {
        this.encryptionParamSet = encryptionParamSet2;
        this.ephemeralPublicKey = ephemeralPublicKey2;
        this.ukm = Arrays.clone(ukm2);
    }

    private GostR3410TransportParameters(ASN1Sequence seq) {
        if (seq.size() == 2) {
            this.encryptionParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            this.ukm = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
            this.ephemeralPublicKey = null;
        } else if (seq.size() == 3) {
            this.encryptionParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            this.ephemeralPublicKey = SubjectPublicKeyInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(1)), false);
            this.ukm = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
        } else {
            throw new IllegalArgumentException("unknown sequence length: " + seq.size());
        }
    }

    public static GostR3410TransportParameters getInstance(Object obj) {
        if (obj instanceof GostR3410TransportParameters) {
            return (GostR3410TransportParameters) obj;
        }
        if (obj != null) {
            return new GostR3410TransportParameters(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static GostR3410TransportParameters getInstance(ASN1TaggedObject obj, boolean explicit) {
        return new GostR3410TransportParameters(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1ObjectIdentifier getEncryptionParamSet() {
        return this.encryptionParamSet;
    }

    public SubjectPublicKeyInfo getEphemeralPublicKey() {
        return this.ephemeralPublicKey;
    }

    public byte[] getUkm() {
        return Arrays.clone(this.ukm);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.encryptionParamSet);
        if (this.ephemeralPublicKey != null) {
            v.add(new DERTaggedObject(false, 0, (ASN1Encodable) this.ephemeralPublicKey));
        }
        v.add(new DEROctetString(this.ukm));
        return new DERSequence(v);
    }
}
