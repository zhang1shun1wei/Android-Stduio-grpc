package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* access modifiers changed from: package-private */
public final class WOTSPlusOid implements XMSSOid {
    private static final Map<String, WOTSPlusOid> oidLookupTable;
    private final int oid;
    private final String stringRepresentation;

    static {
        Map<String, WOTSPlusOid> map = new HashMap<>();
        map.put(createKey("SHA-256", 32, 16, 67), new WOTSPlusOid(16777217, "WOTSP_SHA2-256_W16"));
        map.put(createKey("SHA-512", 64, 16, 131), new WOTSPlusOid(33554434, "WOTSP_SHA2-512_W16"));
        map.put(createKey("SHAKE128", 32, 16, 67), new WOTSPlusOid(50331651, "WOTSP_SHAKE128_W16"));
        map.put(createKey("SHAKE256", 64, 16, 131), new WOTSPlusOid(67108868, "WOTSP_SHAKE256_W16"));
        oidLookupTable = Collections.unmodifiableMap(map);
    }

    private WOTSPlusOid(int oid2, String stringRepresentation2) {
        this.oid = oid2;
        this.stringRepresentation = stringRepresentation2;
    }

    protected static WOTSPlusOid lookup(String algorithmName, int digestSize, int winternitzParameter, int len) {
        if (algorithmName != null) {
            return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len));
        }
        throw new NullPointerException("algorithmName == null");
    }

    private static String createKey(String algorithmName, int digestSize, int winternitzParameter, int len) {
        if (algorithmName != null) {
            return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len;
        }
        throw new NullPointerException("algorithmName == null");
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSOid
    public int getOid() {
        return this.oid;
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSOid
    public String toString() {
        return this.stringRepresentation;
    }
}
