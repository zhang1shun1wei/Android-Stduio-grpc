package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.util.Integers;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class XMSSParameters {
    private static final Map<Integer, XMSSParameters> paramsLookupTable;
    private final int height;
    private final int k;
    private final XMSSOid oid;
    private final String treeDigest;
    private final ASN1ObjectIdentifier treeDigestOID;
    private final int treeDigestSize;
    private final int winternitzParameter;
    private final WOTSPlusParameters wotsPlusParams;

    static {
        Map<Integer, XMSSParameters> pMap = new HashMap<>();
        pMap.put(Integers.valueOf(1), new XMSSParameters(10, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(2), new XMSSParameters(16, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(3), new XMSSParameters(20, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(4), new XMSSParameters(10, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(5), new XMSSParameters(16, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(6), new XMSSParameters(20, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(7), new XMSSParameters(10, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(8), new XMSSParameters(16, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(9), new XMSSParameters(20, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(10), new XMSSParameters(10, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(11), new XMSSParameters(16, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(12), new XMSSParameters(20, NISTObjectIdentifiers.id_shake256));
        paramsLookupTable = Collections.unmodifiableMap(pMap);
    }

    public XMSSParameters(int height2, Digest treeDigest2) {
        this(height2, DigestUtil.getDigestOID(treeDigest2.getAlgorithmName()));
    }

    public XMSSParameters(int height2, ASN1ObjectIdentifier treeDigestOID2) {
        if (height2 < 2) {
            throw new IllegalArgumentException("height must be >= 2");
        } else if (treeDigestOID2 == null) {
            throw new NullPointerException("digest == null");
        } else {
            this.height = height2;
            this.k = determineMinK();
            this.treeDigest = DigestUtil.getDigestName(treeDigestOID2);
            this.treeDigestOID = treeDigestOID2;
            this.wotsPlusParams = new WOTSPlusParameters(treeDigestOID2);
            this.treeDigestSize = this.wotsPlusParams.getTreeDigestSize();
            this.winternitzParameter = this.wotsPlusParams.getWinternitzParameter();
            this.oid = DefaultXMSSOid.lookup(this.treeDigest, this.treeDigestSize, this.winternitzParameter, this.wotsPlusParams.getLen(), height2);
        }
    }

    private int determineMinK() {
        for (int k2 = 2; k2 <= this.height; k2++) {
            if ((this.height - k2) % 2 == 0) {
                return k2;
            }
        }
        throw new IllegalStateException("should never happen...");
    }

    public int getTreeDigestSize() {
        return this.treeDigestSize;
    }

    public ASN1ObjectIdentifier getTreeDigestOID() {
        return this.treeDigestOID;
    }

    public int getHeight() {
        return this.height;
    }

    /* access modifiers changed from: package-private */
    public String getTreeDigest() {
        return this.treeDigest;
    }

    /* access modifiers changed from: package-private */
    public int getLen() {
        return this.wotsPlusParams.getLen();
    }

    /* access modifiers changed from: package-private */
    public int getWinternitzParameter() {
        return this.winternitzParameter;
    }

    /* access modifiers changed from: package-private */
    public WOTSPlus getWOTSPlus() {
        return new WOTSPlus(this.wotsPlusParams);
    }

    /* access modifiers changed from: package-private */
    public XMSSOid getOid() {
        return this.oid;
    }

    /* access modifiers changed from: package-private */
    public int getK() {
        return this.k;
    }

    public static XMSSParameters lookupByOID(int oid2) {
        return paramsLookupTable.get(Integers.valueOf(oid2));
    }
}
