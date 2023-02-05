package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCApplicationProtocolSelector;
import com.mi.car.jsse.easysec.jsse.BCSNIHostName;
import com.mi.car.jsse.easysec.jsse.BCSNIMatcher;
import com.mi.car.jsse.easysec.jsse.BCSNIServerName;
import com.mi.car.jsse.easysec.jsse.provider.JsseUtils;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;

/* access modifiers changed from: package-private */
public abstract class JsseUtils_8 extends JsseUtils_7 {
    JsseUtils_8() {
    }

    static class ExportAPSelector<T> implements BiFunction<T, List<String>, String> {
        private final BCApplicationProtocolSelector<T> selector;

        ExportAPSelector(BCApplicationProtocolSelector<T> selector2) {
            this.selector = selector2;
        }

        public String apply(T t, List<String> u) {
            return this.selector.select(t, u);
        }

        /* access modifiers changed from: package-private */
        public BCApplicationProtocolSelector<T> unwrap() {
            return this.selector;
        }
    }

    /* access modifiers changed from: package-private */
    public static class ExportSNIMatcher extends SNIMatcher {
        private final BCSNIMatcher matcher;

        ExportSNIMatcher(BCSNIMatcher matcher2) {
            super(matcher2.getType());
            this.matcher = matcher2;
        }

        public boolean matches(SNIServerName serverName) {
            return this.matcher.matches(JsseUtils_8.importSNIServerName(serverName));
        }

        /* access modifiers changed from: package-private */
        public BCSNIMatcher unwrap() {
            return this.matcher;
        }
    }

    static class ImportAPSelector<T> implements BCApplicationProtocolSelector<T> {
        private final BiFunction<T, List<String>, String> selector;

        ImportAPSelector(BiFunction<T, List<String>, String> selector2) {
            this.selector = selector2;
        }

        @Override // com.mi.car.jsse.easysec.jsse.BCApplicationProtocolSelector
        public String select(T transport, List<String> protocols) {
            return this.selector.apply(transport, protocols);
        }

        /* access modifiers changed from: package-private */
        public BiFunction<T, List<String>, String> unwrap() {
            return this.selector;
        }
    }

    /* access modifiers changed from: package-private */
    public static class ImportSNIMatcher extends BCSNIMatcher {
        private final SNIMatcher matcher;

        ImportSNIMatcher(SNIMatcher matcher2) {
            super(matcher2.getType());
            this.matcher = matcher2;
        }

        @Override // com.mi.car.jsse.easysec.jsse.BCSNIMatcher
        public boolean matches(BCSNIServerName serverName) {
            return this.matcher.matches(JsseUtils_8.exportSNIServerName(serverName));
        }

        /* access modifiers changed from: package-private */
        public SNIMatcher unwrap() {
            return this.matcher;
        }
    }

    /* access modifiers changed from: package-private */
    public static class UnknownServerName extends SNIServerName {
        UnknownServerName(int type, byte[] encoded) {
            super(type, encoded);
        }
    }

    static void addStatusResponses(CertPathBuilder pkixBuilder, PKIXBuilderParameters pkixParameters, Map<X509Certificate, byte[]> statusResponseMap) {
        if (!statusResponseMap.isEmpty()) {
            List<PKIXCertPathChecker> certPathCheckers = pkixParameters.getCertPathCheckers();
            PKIXRevocationChecker existingChecker = getFirstRevocationChecker(certPathCheckers);
            if (existingChecker != null) {
                Map<X509Certificate, byte[]> ocspResponses = existingChecker.getOcspResponses();
                if (putAnyAbsent(ocspResponses, statusResponseMap) > 0) {
                    existingChecker.setOcspResponses(ocspResponses);
                    pkixParameters.setCertPathCheckers(certPathCheckers);
                }
            } else if (pkixParameters.isRevocationEnabled()) {
                PKIXRevocationChecker checker = (PKIXRevocationChecker) pkixBuilder.getRevocationChecker();
                checker.setOcspResponses(statusResponseMap);
                pkixParameters.addCertPathChecker(checker);
            }
        }
    }

    static <T> BiFunction<T, List<String>, String> exportAPSelector(BCApplicationProtocolSelector<T> selector) {
        if (selector == null) {
            return null;
        }
        if (selector instanceof ImportAPSelector) {
            return ((ImportAPSelector) selector).unwrap();
        }
        return new ExportAPSelector(selector);
    }

    static SNIMatcher exportSNIMatcher(BCSNIMatcher matcher) {
        if (matcher == null) {
            return null;
        }
        if (matcher instanceof ImportSNIMatcher) {
            return ((ImportSNIMatcher) matcher).unwrap();
        }
        return new ExportSNIMatcher(matcher);
    }

    static List<SNIMatcher> exportSNIMatchers(Collection<BCSNIMatcher> matchers) {
        if (matchers == null || matchers.isEmpty()) {
            return Collections.emptyList();
        }
        ArrayList<SNIMatcher> result = new ArrayList<>(matchers.size());
        for (BCSNIMatcher matcher : matchers) {
            result.add(exportSNIMatcher(matcher));
        }
        return Collections.unmodifiableList(result);
    }

    static Object exportSNIMatchersDynamic(Collection<BCSNIMatcher> matchers) {
        return exportSNIMatchers(matchers);
    }

    static SNIServerName exportSNIServerName(BCSNIServerName serverName) {
        if (serverName == null) {
            return null;
        }
        int type = serverName.getType();
        byte[] encoded = serverName.getEncoded();
        switch (type) {
            case 0:
                return new SNIHostName(encoded);
            default:
                return new UnknownServerName(type, encoded);
        }
    }

    static List<SNIServerName> exportSNIServerNames(Collection<BCSNIServerName> serverNames) {
        if (serverNames == null || serverNames.isEmpty()) {
            return Collections.emptyList();
        }
        ArrayList<SNIServerName> result = new ArrayList<>(serverNames.size());
        for (BCSNIServerName serverName : serverNames) {
            result.add(exportSNIServerName(serverName));
        }
        return Collections.unmodifiableList(result);
    }

    static Object exportSNIServerNamesDynamic(Collection<BCSNIServerName> serverNames) {
        return exportSNIServerNames(serverNames);
    }

    static PKIXRevocationChecker getFirstRevocationChecker(List<PKIXCertPathChecker> certPathCheckers) {
        for (PKIXCertPathChecker certPathChecker : certPathCheckers) {
            if (certPathChecker instanceof PKIXRevocationChecker) {
                return (PKIXRevocationChecker) certPathChecker;
            }
        }
        return null;
    }

    static <T> BCApplicationProtocolSelector<T> importAPSelector(BiFunction<T, List<String>, String> selector) {
        if (selector == null) {
            return null;
        }
        if (selector instanceof ExportAPSelector) {
            return ((ExportAPSelector) selector).unwrap();
        }
        return new ImportAPSelector(selector);
    }

    static BCSNIMatcher importSNIMatcher(SNIMatcher matcher) {
        if (matcher == null) {
            return null;
        }
        if (matcher instanceof ExportSNIMatcher) {
            return ((ExportSNIMatcher) matcher).unwrap();
        }
        return new ImportSNIMatcher(matcher);
    }

    static List<BCSNIMatcher> importSNIMatchers(Collection<SNIMatcher> matchers) {
        if (matchers == null || matchers.isEmpty()) {
            return Collections.emptyList();
        }
        ArrayList<BCSNIMatcher> result = new ArrayList<>(matchers.size());
        for (SNIMatcher matcher : matchers) {
            result.add(importSNIMatcher(matcher));
        }
        return Collections.unmodifiableList(result);
    }

    static List<BCSNIMatcher> importSNIMatchersDynamic(Object matchers) {
        return importSNIMatchers((Collection) matchers);
    }

    static BCSNIServerName importSNIServerName(SNIServerName serverName) {
        if (serverName == null) {
            return null;
        }
        int type = serverName.getType();
        byte[] encoded = serverName.getEncoded();
        switch (type) {
            case 0:
                return new BCSNIHostName(encoded);
            default:
                return new BCUnknownServerName(type, encoded);
        }
    }

    static List<BCSNIServerName> importSNIServerNames(Collection<SNIServerName> serverNames) {
        if (serverNames == null || serverNames.isEmpty()) {
            return Collections.emptyList();
        }
        ArrayList<BCSNIServerName> result = new ArrayList<>(serverNames.size());
        for (SNIServerName serverName : serverNames) {
            result.add(importSNIServerName(serverName));
        }
        return Collections.unmodifiableList(result);
    }

    static List<BCSNIServerName> importSNIServerNamesDynamic(Object serverNames) {
        return importSNIServerNames((Collection) serverNames);
    }

    static <K, V> int putAnyAbsent(Map<K, V> to, Map<K, V> from) {
        int count = 0;
        for (Map.Entry<K, V> entry : from.entrySet()) {
            if (to.putIfAbsent(entry.getKey(), entry.getValue()) == null) {
                count++;
            }
        }
        return count;
    }
}
