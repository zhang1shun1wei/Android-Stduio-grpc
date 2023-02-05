package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.util.Arrays;

public class XMSSMTPrivateKey extends ASN1Object {
    private final byte[] bdsState;
    private final long index;
    private final long maxIndex;
    private final byte[] publicSeed;
    private final byte[] root;
    private final byte[] secretKeyPRF;
    private final byte[] secretKeySeed;
    private final int version;

    public XMSSMTPrivateKey(long index2, byte[] secretKeySeed2, byte[] secretKeyPRF2, byte[] publicSeed2, byte[] root2, byte[] bdsState2) {
        this.version = 0;
        this.index = index2;
        this.secretKeySeed = Arrays.clone(secretKeySeed2);
        this.secretKeyPRF = Arrays.clone(secretKeyPRF2);
        this.publicSeed = Arrays.clone(publicSeed2);
        this.root = Arrays.clone(root2);
        this.bdsState = Arrays.clone(bdsState2);
        this.maxIndex = -1;
    }

    public XMSSMTPrivateKey(long index2, byte[] secretKeySeed2, byte[] secretKeyPRF2, byte[] publicSeed2, byte[] root2, byte[] bdsState2, long maxIndex2) {
        this.version = 1;
        this.index = index2;
        this.secretKeySeed = Arrays.clone(secretKeySeed2);
        this.secretKeyPRF = Arrays.clone(secretKeyPRF2);
        this.publicSeed = Arrays.clone(publicSeed2);
        this.root = Arrays.clone(root2);
        this.bdsState = Arrays.clone(bdsState2);
        this.maxIndex = maxIndex2;
    }

    private XMSSMTPrivateKey(ASN1Sequence seq) {
        ASN1Integer v = ASN1Integer.getInstance(seq.getObjectAt(0));
        if (v.hasValue(0) || v.hasValue(1)) {
            this.version = v.intValueExact();
            if (seq.size() == 2 || seq.size() == 3) {
                ASN1Sequence keySeq = ASN1Sequence.getInstance(seq.getObjectAt(1));
                this.index = ASN1Integer.getInstance(keySeq.getObjectAt(0)).longValueExact();
                this.secretKeySeed = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(1)).getOctets());
                this.secretKeyPRF = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(2)).getOctets());
                this.publicSeed = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(3)).getOctets());
                this.root = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(4)).getOctets());
                if (keySeq.size() == 6) {
                    ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(keySeq.getObjectAt(5));
                    if (tagged.getTagNo() != 0) {
                        throw new IllegalArgumentException("unknown tag in XMSSPrivateKey");
                    }
                    this.maxIndex = ASN1Integer.getInstance(tagged, false).longValueExact();
                } else if (keySeq.size() == 5) {
                    this.maxIndex = -1;
                } else {
                    throw new IllegalArgumentException("keySeq should be 5 or 6 in length");
                }
                if (seq.size() == 3) {
                    this.bdsState = Arrays.clone(DEROctetString.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(2)), true).getOctets());
                } else {
                    this.bdsState = null;
                }
            } else {
                throw new IllegalArgumentException("key sequence wrong size");
            }
        } else {
            throw new IllegalArgumentException("unknown version of sequence");
        }
    }

    public static XMSSMTPrivateKey getInstance(Object o) {
        if (o instanceof XMSSMTPrivateKey) {
            return (XMSSMTPrivateKey) o;
        }
        if (o != null) {
            return new XMSSMTPrivateKey(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public int getVersion() {
        return this.version;
    }

    public long getIndex() {
        return this.index;
    }

    public long getMaxIndex() {
        return this.maxIndex;
    }

    public byte[] getSecretKeySeed() {
        return Arrays.clone(this.secretKeySeed);
    }

    public byte[] getSecretKeyPRF() {
        return Arrays.clone(this.secretKeyPRF);
    }

    public byte[] getPublicSeed() {
        return Arrays.clone(this.publicSeed);
    }

    public byte[] getRoot() {
        return Arrays.clone(this.root);
    }

    public byte[] getBdsState() {
        return Arrays.clone(this.bdsState);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.maxIndex >= 0) {
            v.add(new ASN1Integer(1));
        } else {
            v.add(new ASN1Integer(0));
        }
        ASN1EncodableVector vK = new ASN1EncodableVector();
        vK.add(new ASN1Integer(this.index));
        vK.add(new DEROctetString(this.secretKeySeed));
        vK.add(new DEROctetString(this.secretKeyPRF));
        vK.add(new DEROctetString(this.publicSeed));
        vK.add(new DEROctetString(this.root));
        if (this.maxIndex >= 0) {
            vK.add(new DERTaggedObject(false, 0, (ASN1Encodable) new ASN1Integer(this.maxIndex)));
        }
        v.add(new DERSequence(vK));
        v.add(new DERTaggedObject(true, 0, (ASN1Encodable) new DEROctetString(this.bdsState)));
        return new DERSequence(v);
    }
}
