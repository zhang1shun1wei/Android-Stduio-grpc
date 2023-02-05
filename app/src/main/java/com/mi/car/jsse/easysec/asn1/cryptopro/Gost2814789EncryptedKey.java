package com.mi.car.jsse.easysec.asn1.cryptopro;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.util.Arrays;

public class Gost2814789EncryptedKey extends ASN1Object {
    private final byte[] encryptedKey;
    private final byte[] macKey;
    private final byte[] maskKey;

    private Gost2814789EncryptedKey(ASN1Sequence seq) {
        if (seq.size() == 2) {
            this.encryptedKey = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
            this.macKey = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
            this.maskKey = null;
        } else if (seq.size() == 3) {
            this.encryptedKey = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
            this.maskKey = Arrays.clone(ASN1OctetString.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(1)), false).getOctets());
            this.macKey = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
        } else {
            throw new IllegalArgumentException("unknown sequence length: " + seq.size());
        }
    }

    public static Gost2814789EncryptedKey getInstance(Object obj) {
        if (obj instanceof Gost2814789EncryptedKey) {
            return (Gost2814789EncryptedKey) obj;
        }
        if (obj != null) {
            return new Gost2814789EncryptedKey(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public Gost2814789EncryptedKey(byte[] encryptedKey2, byte[] macKey2) {
        this(encryptedKey2, null, macKey2);
    }

    public Gost2814789EncryptedKey(byte[] encryptedKey2, byte[] maskKey2, byte[] macKey2) {
        this.encryptedKey = Arrays.clone(encryptedKey2);
        this.maskKey = Arrays.clone(maskKey2);
        this.macKey = Arrays.clone(macKey2);
    }

    public byte[] getEncryptedKey() {
        return Arrays.clone(this.encryptedKey);
    }

    public byte[] getMaskKey() {
        return Arrays.clone(this.maskKey);
    }

    public byte[] getMacKey() {
        return Arrays.clone(this.macKey);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(new DEROctetString(this.encryptedKey));
        if (this.maskKey != null) {
            v.add(new DERTaggedObject(false, 0, (ASN1Encodable) new DEROctetString(this.encryptedKey)));
        }
        v.add(new DEROctetString(this.macKey));
        return new DERSequence(v);
    }
}
