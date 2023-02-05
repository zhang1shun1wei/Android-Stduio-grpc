package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Xof;

/* access modifiers changed from: package-private */
public final class KeyedHashFunctions {
    private final Digest digest;
    private final int digestSize;

    protected KeyedHashFunctions(ASN1ObjectIdentifier treeDigest, int digestSize2) {
        if (treeDigest == null) {
            throw new NullPointerException("digest == null");
        }
        this.digest = DigestUtil.getDigest(treeDigest);
        this.digestSize = digestSize2;
    }

    private byte[] coreDigest(int fixedValue, byte[] key, byte[] index) {
        byte[] in = XMSSUtil.toBytesBigEndian((long) fixedValue, this.digestSize);
        this.digest.update(in, 0, in.length);
        this.digest.update(key, 0, key.length);
        this.digest.update(index, 0, index.length);
        byte[] out = new byte[this.digestSize];
        if (this.digest instanceof Xof) {
            ((Xof) this.digest).doFinal(out, 0, this.digestSize);
        } else {
            this.digest.doFinal(out, 0);
        }
        return out;
    }

    /* access modifiers changed from: protected */
    public byte[] F(byte[] key, byte[] in) {
        if (key.length != this.digestSize) {
            throw new IllegalArgumentException("wrong key length");
        } else if (in.length == this.digestSize) {
            return coreDigest(0, key, in);
        } else {
            throw new IllegalArgumentException("wrong in length");
        }
    }

    /* access modifiers changed from: protected */
    public byte[] H(byte[] key, byte[] in) {
        if (key.length != this.digestSize) {
            throw new IllegalArgumentException("wrong key length");
        } else if (in.length == this.digestSize * 2) {
            return coreDigest(1, key, in);
        } else {
            throw new IllegalArgumentException("wrong in length");
        }
    }

    /* access modifiers changed from: protected */
    public byte[] HMsg(byte[] key, byte[] in) {
        if (key.length == this.digestSize * 3) {
            return coreDigest(2, key, in);
        }
        throw new IllegalArgumentException("wrong key length");
    }

    /* access modifiers changed from: protected */
    public byte[] PRF(byte[] key, byte[] address) {
        if (key.length != this.digestSize) {
            throw new IllegalArgumentException("wrong key length");
        } else if (address.length == 32) {
            return coreDigest(3, key, address);
        } else {
            throw new IllegalArgumentException("wrong address length");
        }
    }
}
