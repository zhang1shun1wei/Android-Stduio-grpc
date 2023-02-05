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

public class CMCEPrivateKey extends ASN1Object {
    private byte[] C;
    private CMCEPublicKey PublicKey;
    private byte[] alpha;
    private byte[] delta;
    private byte[] g;
    private byte[] s;
    private int version;

    public CMCEPrivateKey(int version2, byte[] delta2, byte[] c, byte[] g2, byte[] alpha2, byte[] s2) {
        this(version2, delta2, c, g2, alpha2, s2, null);
    }

    public CMCEPrivateKey(int version2, byte[] delta2, byte[] c, byte[] g2, byte[] alpha2, byte[] s2, CMCEPublicKey pubKey) {
        this.version = version2;
        if (version2 != 0) {
            throw new IllegalArgumentException("unrecognized version");
        }
        this.delta = Arrays.clone(delta2);
        this.C = Arrays.clone(c);
        this.g = Arrays.clone(g2);
        this.alpha = Arrays.clone(alpha2);
        this.s = Arrays.clone(s2);
        this.PublicKey = pubKey;
    }

    private CMCEPrivateKey(ASN1Sequence seq) {
        this.version = BigIntegers.intValueExact(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        if (this.version != 0) {
            throw new IllegalArgumentException("unrecognized version");
        }
        this.delta = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
        this.C = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
        this.g = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets());
        this.alpha = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(4)).getOctets());
        this.s = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(5)).getOctets());
        if (seq.size() == 7) {
            this.PublicKey = CMCEPublicKey.getInstance(seq.getObjectAt(6));
        }
    }

    public int getVersion() {
        return this.version;
    }

    public byte[] getDelta() {
        return Arrays.clone(this.delta);
    }

    public byte[] getC() {
        return Arrays.clone(this.C);
    }

    public byte[] getG() {
        return Arrays.clone(this.g);
    }

    public byte[] getAlpha() {
        return Arrays.clone(this.alpha);
    }

    public byte[] getS() {
        return Arrays.clone(this.s);
    }

    public CMCEPublicKey getPublicKey() {
        return this.PublicKey;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer((long) this.version));
        v.add(new DEROctetString(this.delta));
        v.add(new DEROctetString(this.C));
        v.add(new DEROctetString(this.g));
        v.add(new DEROctetString(this.alpha));
        v.add(new DEROctetString(this.s));
        if (this.PublicKey != null) {
            v.add(new CMCEPublicKey(this.PublicKey.getT()));
        }
        return new DERSequence(v);
    }

    public static CMCEPrivateKey getInstance(Object o) {
        if (o instanceof CMCEPrivateKey) {
            return (CMCEPrivateKey) o;
        }
        if (o != null) {
            return new CMCEPrivateKey(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
