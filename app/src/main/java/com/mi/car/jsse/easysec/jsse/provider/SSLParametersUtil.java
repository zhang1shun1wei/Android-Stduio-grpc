package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCSNIMatcher;
import com.mi.car.jsse.easysec.jsse.BCSNIServerName;
import com.mi.car.jsse.easysec.jsse.BCSSLParameters;
import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.SSLParameters;

/* access modifiers changed from: package-private */
public abstract class SSLParametersUtil {
    private static final Method getAlgorithmConstraints;
    private static final Method getApplicationProtocols;
    private static final Method getEndpointIdentificationAlgorithm;
    private static final Method getMaximumPacketSize;
    private static final Method getSNIMatchers;
    private static final Method getServerNames;
    private static final Method getUseCipherSuitesOrder;
    private static final Method setAlgorithmConstraints;
    private static final Method setApplicationProtocols;
    private static final Method setEndpointIdentificationAlgorithm;
    private static final Method setMaximumPacketSize;
    private static final Method setSNIMatchers;
    private static final Method setServerNames;
    private static final Method setUseCipherSuitesOrder;

    SSLParametersUtil() {
    }

    static {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLParameters");
        getAlgorithmConstraints = ReflectionUtil.findMethod(methods, "getAlgorithmConstraints");
        setAlgorithmConstraints = ReflectionUtil.findMethod(methods, "setAlgorithmConstraints");
        getApplicationProtocols = ReflectionUtil.findMethod(methods, "getApplicationProtocols");
        setApplicationProtocols = ReflectionUtil.findMethod(methods, "setApplicationProtocols");
        getEndpointIdentificationAlgorithm = ReflectionUtil.findMethod(methods, "getEndpointIdentificationAlgorithm");
        setEndpointIdentificationAlgorithm = ReflectionUtil.findMethod(methods, "setEndpointIdentificationAlgorithm");
        getServerNames = ReflectionUtil.findMethod(methods, "getServerNames");
        setServerNames = ReflectionUtil.findMethod(methods, "setServerNames");
        getSNIMatchers = ReflectionUtil.findMethod(methods, "getSNIMatchers");
        setSNIMatchers = ReflectionUtil.findMethod(methods, "setSNIMatchers");
        getUseCipherSuitesOrder = ReflectionUtil.findMethod(methods, "getUseCipherSuitesOrder");
        setUseCipherSuitesOrder = ReflectionUtil.findMethod(methods, "setUseCipherSuitesOrder");
        getMaximumPacketSize = ReflectionUtil.findMethod(methods, "getMaximumPacketSize");
        setMaximumPacketSize = ReflectionUtil.findMethod(methods, "setMaximumPacketSize");
    }

    static BCSSLParameters getParameters(ProvSSLParameters prov) {
        BCSSLParameters ssl = new BCSSLParameters(prov.getCipherSuites(), prov.getProtocols());
        if (prov.getNeedClientAuth()) {
            ssl.setNeedClientAuth(true);
        } else if (prov.getWantClientAuth()) {
            ssl.setWantClientAuth(true);
        } else {
            ssl.setWantClientAuth(false);
        }
        ssl.setAlgorithmConstraints(prov.getAlgorithmConstraints());
        ssl.setEndpointIdentificationAlgorithm(prov.getEndpointIdentificationAlgorithm());
        ssl.setUseCipherSuitesOrder(prov.getUseCipherSuitesOrder());
        ssl.setServerNames(prov.getServerNames());
        ssl.setSNIMatchers(prov.getSNIMatchers());
        ssl.setApplicationProtocols(prov.getApplicationProtocols());
        ssl.setMaximumPacketSize(prov.getMaximumPacketSize());
        return ssl;
    }

    static SSLParameters getSSLParameters(ProvSSLParameters prov) {
        String[] applicationProtocols;
        Collection<BCSNIMatcher> matchers;
        List<BCSNIServerName> serverNames;
        SSLParameters ssl = new SSLParameters(prov.getCipherSuites(), prov.getProtocols());
        if (prov.getNeedClientAuth()) {
            ssl.setNeedClientAuth(true);
        } else if (prov.getWantClientAuth()) {
            ssl.setWantClientAuth(true);
        } else {
            ssl.setWantClientAuth(false);
        }
        if (setAlgorithmConstraints != null) {
            set(ssl, setAlgorithmConstraints, JsseUtils_7.exportAlgorithmConstraintsDynamic(prov.getAlgorithmConstraints()));
        }
        if (setEndpointIdentificationAlgorithm != null) {
            set(ssl, setEndpointIdentificationAlgorithm, prov.getEndpointIdentificationAlgorithm());
        }
        if (setUseCipherSuitesOrder != null) {
            set(ssl, setUseCipherSuitesOrder, Boolean.valueOf(prov.getUseCipherSuitesOrder()));
        }
        if (!(setServerNames == null || (serverNames = prov.getServerNames()) == null)) {
            set(ssl, setServerNames, JsseUtils_8.exportSNIServerNamesDynamic(serverNames));
        }
        if (!(setSNIMatchers == null || (matchers = prov.getSNIMatchers()) == null)) {
            set(ssl, setSNIMatchers, JsseUtils_8.exportSNIMatchersDynamic(matchers));
        }
        if (!(setApplicationProtocols == null || (applicationProtocols = prov.getApplicationProtocols()) == null)) {
            set(ssl, setApplicationProtocols, applicationProtocols);
        }
        if (setMaximumPacketSize != null) {
            set(ssl, setMaximumPacketSize, Integer.valueOf(prov.getMaximumPacketSize()));
        }
        return ssl;
    }

    static BCSSLParameters importSSLParameters(SSLParameters ssl) {
        String[] applicationProtocols;
        Object matchers;
        Object serverNames;
        String endpointIdentificationAlgorithm;
        Object constraints;
        BCSSLParameters bc = new BCSSLParameters(ssl.getCipherSuites(), ssl.getProtocols());
        if (ssl.getNeedClientAuth()) {
            bc.setNeedClientAuth(true);
        } else if (ssl.getWantClientAuth()) {
            bc.setWantClientAuth(true);
        } else {
            bc.setWantClientAuth(false);
        }
        if (!(getAlgorithmConstraints == null || (constraints = get(ssl, getAlgorithmConstraints)) == null)) {
            bc.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraintsDynamic(constraints));
        }
        if (!(getEndpointIdentificationAlgorithm == null || (endpointIdentificationAlgorithm = (String) get(ssl, getEndpointIdentificationAlgorithm)) == null)) {
            bc.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        }
        if (getUseCipherSuitesOrder != null) {
            bc.setUseCipherSuitesOrder(((Boolean) get(ssl, getUseCipherSuitesOrder)).booleanValue());
        }
        if (!(getServerNames == null || (serverNames = get(ssl, getServerNames)) == null)) {
            bc.setServerNames(JsseUtils_8.importSNIServerNamesDynamic(serverNames));
        }
        if (!(getSNIMatchers == null || (matchers = get(ssl, getSNIMatchers)) == null)) {
            bc.setSNIMatchers(JsseUtils_8.importSNIMatchersDynamic(matchers));
        }
        if (!(getApplicationProtocols == null || (applicationProtocols = (String[]) get(ssl, getApplicationProtocols)) == null)) {
            bc.setApplicationProtocols(applicationProtocols);
        }
        if (getMaximumPacketSize != null) {
            bc.setMaximumPacketSize(((Integer) get(ssl, getMaximumPacketSize)).intValue());
        }
        return bc;
    }

    static void setParameters(ProvSSLParameters prov, BCSSLParameters ssl) {
        String[] cipherSuites = ssl.getCipherSuites();
        if (cipherSuites != null) {
            prov.setCipherSuites(cipherSuites);
        }
        String[] protocols = ssl.getProtocols();
        if (protocols != null) {
            prov.setProtocols(protocols);
        }
        if (ssl.getNeedClientAuth()) {
            prov.setNeedClientAuth(true);
        } else if (ssl.getWantClientAuth()) {
            prov.setWantClientAuth(true);
        } else {
            prov.setWantClientAuth(false);
        }
        BCAlgorithmConstraints algorithmConstraints = ssl.getAlgorithmConstraints();
        if (algorithmConstraints != null) {
            prov.setAlgorithmConstraints(algorithmConstraints);
        }
        String endpointIdentificationAlgorithm = ssl.getEndpointIdentificationAlgorithm();
        if (endpointIdentificationAlgorithm != null) {
            prov.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        }
        prov.setUseCipherSuitesOrder(ssl.getUseCipherSuitesOrder());
        List<BCSNIServerName> serverNames = ssl.getServerNames();
        if (serverNames != null) {
            prov.setServerNames(serverNames);
        }
        Collection<BCSNIMatcher> sniMatchers = ssl.getSNIMatchers();
        if (sniMatchers != null) {
            prov.setSNIMatchers(sniMatchers);
        }
        String[] applicationProtocols = ssl.getApplicationProtocols();
        if (applicationProtocols != null) {
            prov.setApplicationProtocols(applicationProtocols);
        }
        prov.setMaximumPacketSize(ssl.getMaximumPacketSize());
    }

    static void setSSLParameters(ProvSSLParameters prov, SSLParameters ssl) {
        String[] applicationProtocols;
        Object matchers;
        Object serverNames;
        String endpointIdentificationAlgorithm;
        Object constraints;
        String[] cipherSuites = ssl.getCipherSuites();
        if (cipherSuites != null) {
            prov.setCipherSuites(cipherSuites);
        }
        String[] protocols = ssl.getProtocols();
        if (protocols != null) {
            prov.setProtocols(protocols);
        }
        if (ssl.getNeedClientAuth()) {
            prov.setNeedClientAuth(true);
        } else if (ssl.getWantClientAuth()) {
            prov.setWantClientAuth(true);
        } else {
            prov.setWantClientAuth(false);
        }
        if (!(getAlgorithmConstraints == null || (constraints = get(ssl, getAlgorithmConstraints)) == null)) {
            prov.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraintsDynamic(constraints));
        }
        if (!(getEndpointIdentificationAlgorithm == null || (endpointIdentificationAlgorithm = (String) get(ssl, getEndpointIdentificationAlgorithm)) == null)) {
            prov.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        }
        if (getUseCipherSuitesOrder != null) {
            prov.setUseCipherSuitesOrder(((Boolean) get(ssl, getUseCipherSuitesOrder)).booleanValue());
        }
        if (!(getServerNames == null || (serverNames = get(ssl, getServerNames)) == null)) {
            prov.setServerNames(JsseUtils_8.importSNIServerNamesDynamic(serverNames));
        }
        if (!(getSNIMatchers == null || (matchers = get(ssl, getSNIMatchers)) == null)) {
            prov.setSNIMatchers(JsseUtils_8.importSNIMatchersDynamic(matchers));
        }
        if (!(getApplicationProtocols == null || (applicationProtocols = (String[]) get(ssl, getApplicationProtocols)) == null)) {
            prov.setApplicationProtocols(applicationProtocols);
        }
        if (getMaximumPacketSize != null) {
            prov.setMaximumPacketSize(((Integer) get(ssl, getMaximumPacketSize)).intValue());
        }
    }

    private static Object get(Object obj, Method method) {
        return ReflectionUtil.invokeGetter(obj, method);
    }

    private static void set(Object obj, Method method, Object arg) {
        ReflectionUtil.invokeSetter(obj, method, arg);
    }
}
