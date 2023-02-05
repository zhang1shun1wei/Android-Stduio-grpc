package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.crypto.Digest;

/* access modifiers changed from: package-private */
public final class WOTSPlusParameters {
    private final int digestSize;
    private final int len;
    private final int len1;
    private final int len2;
    private final XMSSOid oid;
    private final ASN1ObjectIdentifier treeDigest;
    private final int winternitzParameter;

    protected WOTSPlusParameters(ASN1ObjectIdentifier treeDigest2) {
        if (treeDigest2 == null) {
            throw new NullPointerException("treeDigest == null");
        }
        this.treeDigest = treeDigest2;
        Digest digest = DigestUtil.getDigest(treeDigest2);
        this.digestSize = XMSSUtil.getDigestSize(digest);
        this.winternitzParameter = 16;
        this.len1 = (int) Math.ceil(((double) (this.digestSize * 8)) / ((double) XMSSUtil.log2(this.winternitzParameter)));
        this.len2 = ((int) Math.floor((double) (XMSSUtil.log2(this.len1 * (this.winternitzParameter - 1)) / XMSSUtil.log2(this.winternitzParameter)))) + 1;
        this.len = this.len1 + this.len2;
        this.oid = WOTSPlusOid.lookup(digest.getAlgorithmName(), this.digestSize, this.winternitzParameter, this.len);
        if (this.oid == null) {
            throw new IllegalArgumentException("cannot find OID for digest algorithm: " + digest.getAlgorithmName());
        }
    }

    /* access modifiers changed from: protected */
    public XMSSOid getOid() {
        return this.oid;
    }

    /* access modifiers changed from: protected */
    public int getTreeDigestSize() {
        return this.digestSize;
    }

    /* access modifiers changed from: protected */
    public int getWinternitzParameter() {
        return this.winternitzParameter;
    }

    /* access modifiers changed from: protected */
    public int getLen() {
        return this.len;
    }

    /* access modifiers changed from: protected */
    public int getLen1() {
        return this.len1;
    }

    /* access modifiers changed from: protected */
    public int getLen2() {
        return this.len2;
    }

    public ASN1ObjectIdentifier getTreeDigest() {
        return this.treeDigest;
    }
}
