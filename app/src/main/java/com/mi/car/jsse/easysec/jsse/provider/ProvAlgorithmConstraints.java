package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.jsse.java.security.BCCryptoPrimitive;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/* access modifiers changed from: package-private */
public class ProvAlgorithmConstraints extends AbstractAlgorithmConstraints {
    static final ProvAlgorithmConstraints DEFAULT = new ProvAlgorithmConstraints(null, true);
    private static final String DEFAULT_CERTPATH_DISABLED_ALGORITHMS = "MD2, MD5, SHA1 jdkCA & usage TLSServer, RSA keySize < 1024, DSA keySize < 1024, EC keySize < 224, include jdk.disabled.namedCurves";
    private static final String DEFAULT_TLS_DISABLED_ALGORITHMS = "SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, include jdk.disabled.namedCurves";
    static final ProvAlgorithmConstraints DEFAULT_TLS_ONLY = new ProvAlgorithmConstraints(null, false);
    private static final Logger LOG = Logger.getLogger(ProvAlgorithmConstraints.class.getName());
    private static final String PROPERTY_CERTPATH_DISABLED_ALGORITHMS = "jdk.certpath.disabledAlgorithms";
    private static final String PROPERTY_TLS_DISABLED_ALGORITHMS = "jdk.tls.disabledAlgorithms";
    private static final DisabledAlgorithmConstraints provTlsDisabledAlgorithms = DisabledAlgorithmConstraints.create(ProvAlgorithmDecomposer.INSTANCE_TLS, PROPERTY_TLS_DISABLED_ALGORITHMS, DEFAULT_TLS_DISABLED_ALGORITHMS);
    private static final DisabledAlgorithmConstraints provX509DisabledAlgorithms = DisabledAlgorithmConstraints.create(ProvAlgorithmDecomposer.INSTANCE_X509, PROPERTY_CERTPATH_DISABLED_ALGORITHMS, DEFAULT_CERTPATH_DISABLED_ALGORITHMS);
    private final BCAlgorithmConstraints configAlgorithmConstraints;
    private final boolean enableX509Constraints;
    private final Set<String> supportedSignatureAlgorithms;

    ProvAlgorithmConstraints(BCAlgorithmConstraints configAlgorithmConstraints2, boolean enableX509Constraints2) {
        super(null);
        this.configAlgorithmConstraints = configAlgorithmConstraints2;
        this.supportedSignatureAlgorithms = null;
        this.enableX509Constraints = enableX509Constraints2;
    }

    ProvAlgorithmConstraints(BCAlgorithmConstraints configAlgorithmConstraints2, String[] supportedSignatureAlgorithms2, boolean enableX509Constraints2) {
        super(null);
        this.configAlgorithmConstraints = configAlgorithmConstraints2;
        this.supportedSignatureAlgorithms = asUnmodifiableSet(supportedSignatureAlgorithms2);
        this.enableX509Constraints = enableX509Constraints2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints
    public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
        checkPrimitives(primitives);
        checkAlgorithmName(algorithm);
        if (this.supportedSignatureAlgorithms != null) {
            algorithm = getAlgorithm(algorithm);
            if (!isSupportedSignatureAlgorithm(algorithm)) {
                if (!LOG.isLoggable(Level.FINEST)) {
                    return false;
                }
                LOG.finest("Signature algorithm '" + algorithm + "' not in supported signature algorithms");
                return false;
            }
        }
        if (this.configAlgorithmConstraints != null && !this.configAlgorithmConstraints.permits(primitives, algorithm, parameters)) {
            return false;
        }
        if (provTlsDisabledAlgorithms != null && !provTlsDisabledAlgorithms.permits(primitives, algorithm, parameters)) {
            return false;
        }
        if (!this.enableX509Constraints || provX509DisabledAlgorithms == null || provX509DisabledAlgorithms.permits(primitives, algorithm, parameters)) {
            return true;
        }
        return false;
    }

    @Override // com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints
    public boolean permits(Set<BCCryptoPrimitive> primitives, Key key) {
        checkPrimitives(primitives);
        checkKey(key);
        if (this.configAlgorithmConstraints != null && !this.configAlgorithmConstraints.permits(primitives, key)) {
            return false;
        }
        if (provTlsDisabledAlgorithms != null && !provTlsDisabledAlgorithms.permits(primitives, key)) {
            return false;
        }
        if (!this.enableX509Constraints || provX509DisabledAlgorithms == null || provX509DisabledAlgorithms.permits(primitives, key)) {
            return true;
        }
        return false;
    }

    @Override // com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints
    public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
        checkPrimitives(primitives);
        checkAlgorithmName(algorithm);
        checkKey(key);
        if (this.supportedSignatureAlgorithms != null) {
            algorithm = getAlgorithm(algorithm);
            if (!isSupportedSignatureAlgorithm(algorithm)) {
                if (!LOG.isLoggable(Level.FINEST)) {
                    return false;
                }
                LOG.finest("Signature algorithm '" + algorithm + "' not in supported signature algorithms");
                return false;
            }
        }
        if (this.configAlgorithmConstraints != null && !this.configAlgorithmConstraints.permits(primitives, algorithm, key, parameters)) {
            return false;
        }
        if (provTlsDisabledAlgorithms != null && !provTlsDisabledAlgorithms.permits(primitives, algorithm, key, parameters)) {
            return false;
        }
        if (!this.enableX509Constraints || provX509DisabledAlgorithms == null || provX509DisabledAlgorithms.permits(primitives, algorithm, key, parameters)) {
            return true;
        }
        return false;
    }

    private String getAlgorithm(String algorithmBC) {
        int colonPos = algorithmBC.indexOf(58);
        return colonPos < 0 ? algorithmBC : algorithmBC.substring(0, colonPos);
    }

    private boolean isSupportedSignatureAlgorithm(String algorithmBC) {
        return containsIgnoreCase(this.supportedSignatureAlgorithms, algorithmBC);
    }
}
