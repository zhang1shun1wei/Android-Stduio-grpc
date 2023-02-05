package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;

public class XMSSMTPublicKey extends ASN1Object {
    private final byte[] publicSeed;
    private final byte[] root;

    public XMSSMTPublicKey(byte[] publicSeed2, byte[] root2) {
        this.publicSeed = Arrays.clone(publicSeed2);
        this.root = Arrays.clone(root2);
    }

    private XMSSMTPublicKey(ASN1Sequence seq) {
        if (!ASN1Integer.getInstance(seq.getObjectAt(0)).hasValue(0)) {
            throw new IllegalArgumentException("unknown version of sequence");
        }
        this.publicSeed = Arrays.clone(DEROctetString.getInstance(seq.getObjectAt(1)).getOctets());
        this.root = Arrays.clone(DEROctetString.getInstance(seq.getObjectAt(2)).getOctets());
    }

    public static XMSSMTPublicKey getInstance(Object o) {
        if (o instanceof XMSSMTPublicKey) {
            return (XMSSMTPublicKey) o;
        }
        if (o != null) {
            return new XMSSMTPublicKey(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public byte[] getPublicSeed() {
        return Arrays.clone(this.publicSeed);
    }

    public byte[] getRoot() {
        return Arrays.clone(this.root);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(0));
        v.add(new DEROctetString(this.publicSeed));
        v.add(new DEROctetString(this.root));
        return new DERSequence(v);
    }
}
