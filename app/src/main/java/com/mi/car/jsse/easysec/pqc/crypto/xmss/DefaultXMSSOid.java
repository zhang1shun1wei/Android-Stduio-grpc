package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class DefaultXMSSOid implements XMSSOid {
    private static final Map<String, DefaultXMSSOid> oidLookupTable;
    private final int oid;
    private final String stringRepresentation;

    static {
        Map<String, DefaultXMSSOid> map = new HashMap<>();
        map.put(createKey("SHA-256", 32, 16, 67, 10), new DefaultXMSSOid(1, "XMSS_SHA2_10_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 16), new DefaultXMSSOid(2, "XMSS_SHA2_16_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 20), new DefaultXMSSOid(3, "XMSS_SHA2_20_256"));
        map.put(createKey("SHA-512", 64, 16, 131, 10), new DefaultXMSSOid(4, "XMSS_SHA2_10_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 16), new DefaultXMSSOid(5, "XMSS_SHA2_16_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 20), new DefaultXMSSOid(6, "XMSS_SHA2_20_512"));
        map.put(createKey("SHAKE128", 32, 16, 67, 10), new DefaultXMSSOid(7, "XMSS_SHAKE_10_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 16), new DefaultXMSSOid(8, "XMSS_SHAKE_16_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 20), new DefaultXMSSOid(9, "XMSS_SHAKE_20_256"));
        map.put(createKey("SHAKE256", 64, 16, 131, 10), new DefaultXMSSOid(10, "XMSS_SHAKE_10_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 16), new DefaultXMSSOid(11, "XMSS_SHAKE_16_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 20), new DefaultXMSSOid(12, "XMSS_SHAKE_20_512"));
        oidLookupTable = Collections.unmodifiableMap(map);
    }

    private DefaultXMSSOid(int oid2, String stringRepresentation2) {
        this.oid = oid2;
        this.stringRepresentation = stringRepresentation2;
    }

    public static DefaultXMSSOid lookup(String algorithmName, int digestSize, int winternitzParameter, int len, int height) {
        if (algorithmName != null) {
            return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len, height));
        }
        throw new NullPointerException("algorithmName == null");
    }

    private static String createKey(String algorithmName, int digestSize, int winternitzParameter, int len, int height) {
        if (algorithmName != null) {
            return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len + "-" + height;
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
