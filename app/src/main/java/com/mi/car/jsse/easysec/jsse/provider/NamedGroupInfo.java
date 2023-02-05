package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.jsse.java.security.BCCryptoPrimitive;
import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCrypto;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;
import java.security.AlgorithmParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Vector;
import java.util.logging.Logger;

/* access modifiers changed from: package-private */
public class NamedGroupInfo {
    private static final int[] CANDIDATES_DEFAULT = {29, 30, 23, 24, 25, 31, 32, 33, NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096};
    private static final Logger LOG = Logger.getLogger(NamedGroupInfo.class.getName());
    private static final String PROPERTY_NAMED_GROUPS = "jdk.tls.namedGroups";
    private final AlgorithmParameters algorithmParameters;
    private final All all;
    private final boolean enabled;

    /* access modifiers changed from: private */
    public enum All {
        sect163k1(1, "EC"),
        sect163r1(2, "EC"),
        sect163r2(3, "EC"),
        sect193r1(4, "EC"),
        sect193r2(5, "EC"),
        sect233k1(6, "EC"),
        sect233r1(7, "EC"),
        sect239k1(8, "EC"),
        sect283k1(9, "EC"),
        sect283r1(10, "EC"),
        sect409k1(11, "EC"),
        sect409r1(12, "EC"),
        sect571k1(13, "EC"),
        sect571r1(14, "EC"),
        secp160k1(15, "EC"),
        secp160r1(16, "EC"),
        secp160r2(17, "EC"),
        secp192k1(18, "EC"),
        secp192r1(19, "EC"),
        secp224k1(20, "EC"),
        secp224r1(21, "EC"),
        secp256k1(22, "EC"),
        secp256r1(23, "EC"),
        secp384r1(24, "EC"),
        secp521r1(25, "EC"),
        brainpoolP256r1(26, "EC"),
        brainpoolP384r1(27, "EC"),
        brainpoolP512r1(28, "EC"),
        x25519(29, "XDH"),
        x448(30, "XDH"),
        brainpoolP256r1tls13(31, "EC"),
        brainpoolP384r1tls13(32, "EC"),
        brainpoolP512r1tls13(33, "EC"),
        curveSM2(41, "EC"),
        ffdhe2048(NamedGroup.ffdhe2048, "DiffieHellman"),
        ffdhe3072(NamedGroup.ffdhe3072, "DiffieHellman"),
        ffdhe4096(NamedGroup.ffdhe4096, "DiffieHellman"),
        ffdhe6144(NamedGroup.ffdhe6144, "DiffieHellman"),
        ffdhe8192(NamedGroup.ffdhe8192, "DiffieHellman");
        
        private final int bitsECDH;
        private final int bitsFFDHE;
        private final boolean char2;
        private final String jcaAlgorithm;
        private final String jcaGroup;
        private final String name;
        private final int namedGroup;
        private final boolean supportedPost13;
        private final boolean supportedPre13;
        private final String text;

        private All(int namedGroup2, String jcaAlgorithm2) {
            this.namedGroup = namedGroup2;
            this.name = NamedGroup.getName(namedGroup2);
            this.text = NamedGroup.getText(namedGroup2);
            this.jcaAlgorithm = jcaAlgorithm2;
            this.jcaGroup = NamedGroup.getStandardName(namedGroup2);
            this.supportedPost13 = NamedGroup.canBeNegotiated(namedGroup2, ProtocolVersion.TLSv13);
            this.supportedPre13 = NamedGroup.canBeNegotiated(namedGroup2, ProtocolVersion.TLSv12);
            this.char2 = NamedGroup.isChar2Curve(namedGroup2);
            this.bitsECDH = NamedGroup.getCurveBits(namedGroup2);
            this.bitsFFDHE = NamedGroup.getFiniteFieldBits(namedGroup2);
        }
    }

    /* access modifiers changed from: package-private */
    public static class PerConnection {
        private final Map<Integer, NamedGroupInfo> local;
        private final boolean localECDSA;
        private List<NamedGroupInfo> peer = null;

        PerConnection(Map<Integer, NamedGroupInfo> local2, boolean localECDSA2) {
            this.local = local2;
            this.localECDSA = localECDSA2;
        }

        public synchronized List<NamedGroupInfo> getPeer() {
            return this.peer;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private synchronized void setPeer(List<NamedGroupInfo> peer2) {
            this.peer = peer2;
        }
    }

    /* access modifiers changed from: package-private */
    public static class PerContext {
        private final int[] candidates;
        private final Map<Integer, NamedGroupInfo> index;

        PerContext(Map<Integer, NamedGroupInfo> index2, int[] candidates2) {
            this.index = index2;
            this.candidates = candidates2;
        }
    }

    static PerConnection createPerConnection(PerContext perContext, ProvSSLParameters sslParameters, ProtocolVersion[] activeProtocolVersions) {
        Map<Integer, NamedGroupInfo> local = createLocal(perContext, sslParameters, activeProtocolVersions);
        return new PerConnection(local, createLocalECDSA(local));
    }

    static PerContext createPerContext(boolean isFipsContext, JcaTlsCrypto crypto) {
        Map<Integer, NamedGroupInfo> index = createIndex(isFipsContext, crypto);
        return new PerContext(index, createCandidates(index));
    }

    static int getMaximumBitsServerECDH(PerConnection perConnection) {
        int maxBits = 0;
        for (NamedGroupInfo namedGroupInfo : getEffectivePeer(perConnection)) {
            maxBits = Math.max(maxBits, namedGroupInfo.getBitsECDH());
        }
        return maxBits;
    }

    static int getMaximumBitsServerFFDHE(PerConnection perConnection) {
        int maxBits = 0;
        for (NamedGroupInfo namedGroupInfo : getEffectivePeer(perConnection)) {
            maxBits = Math.max(maxBits, namedGroupInfo.getBitsFFDHE());
        }
        return maxBits;
    }

    static NamedGroupInfo getNamedGroup(PerContext perContext, int namedGroup) {
        return (NamedGroupInfo) perContext.index.get(Integer.valueOf(namedGroup));
    }

    static Vector<Integer> getSupportedGroupsLocalClient(PerConnection perConnection) {
        return new Vector<>(perConnection.local.keySet());
    }

    static int[] getSupportedGroupsLocalServer(PerConnection perConnection) {
        Set<Integer> keys = perConnection.local.keySet();
        int pos = 0;
        int[] result = new int[keys.size()];
        for (Integer key : keys) {
            result[pos] = key.intValue();
            pos++;
        }
        return result;
    }

    static boolean hasAnyECDSALocal(PerConnection perConnection) {
        return perConnection.localECDSA;
    }

    static boolean hasLocal(PerConnection perConnection, int namedGroup) {
        return perConnection.local.containsKey(Integer.valueOf(namedGroup));
    }

    static void notifyPeer(PerConnection perConnection, int[] peerNamedGroups) {
        perConnection.setPeer(createPeer(perConnection, peerNamedGroups));
    }

    static int selectServerECDH(PerConnection perConnection, int minimumBitsECDH) {
        for (NamedGroupInfo namedGroupInfo : getEffectivePeer(perConnection)) {
            if (namedGroupInfo.getBitsECDH() >= minimumBitsECDH) {
                return namedGroupInfo.getNamedGroup();
            }
        }
        return -1;
    }

    static int selectServerFFDHE(PerConnection perConnection, int minimumBitsFFDHE) {
        for (NamedGroupInfo namedGroupInfo : getEffectivePeer(perConnection)) {
            if (namedGroupInfo.getBitsFFDHE() >= minimumBitsFFDHE) {
                return namedGroupInfo.getNamedGroup();
            }
        }
        return -1;
    }

    private static void addNamedGroup(boolean isFipsContext, JcaTlsCrypto crypto, boolean disableChar2, boolean disableFFDHE, Map<Integer, NamedGroupInfo> ng, All all2) {
        boolean disable;
        boolean enabled2 = true;
        int namedGroup = all2.namedGroup;
        if (!isFipsContext || FipsUtils.isFipsNamedGroup(namedGroup)) {
            if ((!disableChar2 || !all2.char2) && (!disableFFDHE || all2.bitsFFDHE <= 0)) {
                disable = false;
            } else {
                disable = true;
            }
            if (disable || all2.jcaGroup == null || !crypto.hasNamedGroup(namedGroup)) {
                enabled2 = false;
            }
            AlgorithmParameters algorithmParameters2 = null;
            if (enabled2) {
                try {
                    algorithmParameters2 = crypto.getNamedGroupAlgorithmParameters(namedGroup);
                } catch (Exception e) {
                    enabled2 = false;
                }
            }
            if (ng.put(Integer.valueOf(namedGroup), new NamedGroupInfo(all2, algorithmParameters2, enabled2)) != null) {
                throw new IllegalStateException("Duplicate entries for NamedGroupInfo");
            }
        }
    }

    private static int[] createCandidates(Map<Integer, NamedGroupInfo> index) {
        int count;
        String[] names = PropertyUtils.getStringArraySystemProperty(PROPERTY_NAMED_GROUPS);
        if (names == null) {
            return CANDIDATES_DEFAULT;
        }
        int[] result = new int[names.length];
        int length = names.length;
        int i = 0;
        int count2 = 0;
        while (i < length) {
            String name = names[i];
            int namedGroup = getNamedGroupByName(name);
            if (namedGroup < 0) {
                LOG.warning("'jdk.tls.namedGroups' contains unrecognised NamedGroup: " + name);
                count = count2;
            } else {
                NamedGroupInfo namedGroupInfo = index.get(Integer.valueOf(namedGroup));
                if (namedGroupInfo == null) {
                    LOG.warning("'jdk.tls.namedGroups' contains unsupported NamedGroup: " + name);
                    count = count2;
                } else if (!namedGroupInfo.isEnabled()) {
                    LOG.warning("'jdk.tls.namedGroups' contains disabled NamedGroup: " + name);
                    count = count2;
                } else {
                    count = count2 + 1;
                    result[count2] = namedGroup;
                }
            }
            i++;
            count2 = count;
        }
        if (count2 < result.length) {
            result = Arrays.copyOf(result, count2);
        }
        if (result.length >= 1) {
            return result;
        }
        LOG.severe("'jdk.tls.namedGroups' contained no usable NamedGroup values");
        return result;
    }

    private static Map<Integer, NamedGroupInfo> createIndex(boolean isFipsContext, JcaTlsCrypto crypto) {
        Map<Integer, NamedGroupInfo> ng = new TreeMap<>();
        boolean disableChar2 = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.ec.disableChar2", false) || PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.ec.disable_f2m", false);
        boolean disableFFDHE = !PropertyUtils.getBooleanSystemProperty("jsse.enableFFDHE", true);
        for (All all2 : All.values()) {
            addNamedGroup(isFipsContext, crypto, disableChar2, disableFFDHE, ng, all2);
        }
        return ng;
    }

    private static Map<Integer, NamedGroupInfo> createLocal(PerContext perContext, ProvSSLParameters sslParameters, ProtocolVersion[] activeProtocolVersions) {
        ProtocolVersion latest = ProtocolVersion.getLatestTLS(activeProtocolVersions);
        ProtocolVersion earliest = ProtocolVersion.getEarliestTLS(activeProtocolVersions);
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();
        boolean post13Active = TlsUtils.isTLSv13(latest);
        boolean pre13Active = !TlsUtils.isTLSv13(earliest);
        int count = perContext.candidates.length;
        LinkedHashMap<Integer, NamedGroupInfo> result = new LinkedHashMap<>(count);
        for (int i = 0; i < count; i++) {
            Integer candidate = Integers.valueOf(perContext.candidates[i]);
            NamedGroupInfo namedGroupInfo = (NamedGroupInfo) perContext.index.get(candidate);
            if (namedGroupInfo != null && namedGroupInfo.isActive(algorithmConstraints, post13Active, pre13Active)) {
                result.put(candidate, namedGroupInfo);
            }
        }
        return result;
    }

    private static boolean createLocalECDSA(Map<Integer, NamedGroupInfo> local) {
        for (NamedGroupInfo namedGroupInfo : local.values()) {
            if (NamedGroup.refersToAnECDSACurve(namedGroupInfo.getNamedGroup())) {
                return true;
            }
        }
        return false;
    }

    private static List<NamedGroupInfo> createPeer(PerConnection perConnection, int[] peerNamedGroups) {
        return getNamedGroupInfos(perConnection.local, peerNamedGroups);
    }

    private static Collection<NamedGroupInfo> getEffectivePeer(PerConnection perConnection) {
        List<NamedGroupInfo> peer = perConnection.getPeer();
        return !peer.isEmpty() ? peer : perConnection.local.values();
    }

    private static int getNamedGroupByName(String name) {
        All[] values = All.values();
        for (All all2 : values) {
            if (all2.name.equalsIgnoreCase(name)) {
                return all2.namedGroup;
            }
        }
        return -1;
    }

    private static List<NamedGroupInfo> getNamedGroupInfos(Map<Integer, NamedGroupInfo> namedGroupInfos, int[] namedGroups) {
        if (TlsUtils.isNullOrEmpty(namedGroups)) {
            return Collections.emptyList();
        }
        int count = namedGroups.length;
        ArrayList<NamedGroupInfo> result = new ArrayList<>(count);
        for (int namedGroup : namedGroups) {
            NamedGroupInfo namedGroupInfo = namedGroupInfos.get(Integer.valueOf(namedGroup));
            if (namedGroupInfo != null) {
                result.add(namedGroupInfo);
            }
        }
        if (result.isEmpty()) {
            return Collections.emptyList();
        }
        result.trimToSize();
        return result;
    }

    NamedGroupInfo(All all2, AlgorithmParameters algorithmParameters2, boolean enabled2) {
        this.all = all2;
        this.algorithmParameters = algorithmParameters2;
        this.enabled = enabled2;
    }

    /* access modifiers changed from: package-private */
    public int getBitsECDH() {
        return this.all.bitsECDH;
    }

    /* access modifiers changed from: package-private */
    public int getBitsFFDHE() {
        return this.all.bitsFFDHE;
    }

    /* access modifiers changed from: package-private */
    public String getJcaAlgorithm() {
        return this.all.jcaAlgorithm;
    }

    /* access modifiers changed from: package-private */
    public String getJcaGroup() {
        return this.all.jcaGroup;
    }

    /* access modifiers changed from: package-private */
    public int getNamedGroup() {
        return this.all.namedGroup;
    }

    /* access modifiers changed from: package-private */
    public boolean isActive(BCAlgorithmConstraints algorithmConstraints, boolean post13Active, boolean pre13Active) {
        return this.enabled && ((post13Active && isSupportedPost13()) || (pre13Active && isSupportedPre13())) && isPermittedBy(algorithmConstraints);
    }

    /* access modifiers changed from: package-private */
    public boolean isEnabled() {
        return this.enabled;
    }

    /* access modifiers changed from: package-private */
    public boolean isSupportedPost13() {
        return this.all.supportedPost13;
    }

    /* access modifiers changed from: package-private */
    public boolean isSupportedPre13() {
        return this.all.supportedPre13;
    }

    public String toString() {
        return this.all.text;
    }

    private boolean isPermittedBy(BCAlgorithmConstraints algorithmConstraints) {
        Set<BCCryptoPrimitive> primitives = JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;
        return algorithmConstraints.permits(primitives, getJcaGroup(), null) && algorithmConstraints.permits(primitives, getJcaAlgorithm(), this.algorithmParameters);
    }
}
