package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.BigIntegers;

public class SABERPrivateKey extends ASN1Object {
    private SABERPublicKey PublicKey;
    private byte[] hpk;
    private byte[] s;
    private int version;
    private byte[] z;

    public SABERPrivateKey(int version2, byte[] z2, byte[] s2, byte[] hpk2) {
        this.version = version2;
        if (version2 != 0) {
            throw new IllegalArgumentException("unrecognized version");
        }
        this.z = z2;
        this.s = s2;
        this.hpk = hpk2;
    }

    public SABERPrivateKey(int version2, byte[] z2, byte[] s2, byte[] hpk2, SABERPublicKey publicKey) {
        this.version = version2;
        if (version2 != 0) {
            throw new IllegalArgumentException("unrecognized version");
        }
        this.z = z2;
        this.s = s2;
        this.hpk = hpk2;
        this.PublicKey = publicKey;
    }

    private SABERPrivateKey(ASN1Sequence seq) {
        this.version = BigIntegers.intValueExact(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        if (this.version != 0) {
            throw new IllegalArgumentException("unrecognized version");
        }
        this.z = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
        this.s = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
        this.PublicKey = SABERPublicKey.getInstance(seq.getObjectAt(3));
        this.hpk = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(4)).getOctets());
    }

    public int getVersion() {
        return this.version;
    }

    public byte[] getZ() {
        return this.z;
    }

    public byte[] getS() {
        return this.s;
    }

    public byte[] getHpk() {
        return this.hpk;
    }

    public SABERPublicKey getPublicKey() {
        return this.PublicKey;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer((long) this.version));
        v.add(new DEROctetString(this.z));
        v.add(new DEROctetString(this.s));
        v.add(new DEROctetString(this.hpk));
        return new DERSequence(v);
    }

    public static SABERPrivateKey getInstance(Object o) {
        if (o instanceof SABERPrivateKey) {
            return (SABERPrivateKey) o;
        }
        if (o != null) {
            return new SABERPrivateKey(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
