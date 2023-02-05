package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.tls.CipherSuite;
import java.util.Set;

class ProvAlgorithmDecomposer extends JcaAlgorithmDecomposer {
    static final ProvAlgorithmDecomposer INSTANCE_TLS = new ProvAlgorithmDecomposer(true);
    static final ProvAlgorithmDecomposer INSTANCE_X509 = new ProvAlgorithmDecomposer(false);
    private final boolean enableTLSAlgorithms;

    private ProvAlgorithmDecomposer(boolean enableTLSAlgorithms2) {
        this.enableTLSAlgorithms = enableTLSAlgorithms2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.AlgorithmDecomposer, com.mi.car.jsse.easysec.jsse.provider.JcaAlgorithmDecomposer
    public Set<String> decompose(String algorithm) {
        CipherSuiteInfo cipherSuiteInfo;
        if (!algorithm.startsWith("TLS_") || (cipherSuiteInfo = ProvSSLContextSpi.getCipherSuiteInfo(algorithm)) == null || CipherSuite.isSCSV(cipherSuiteInfo.getCipherSuite())) {
            return super.decompose(algorithm);
        }
        if (this.enableTLSAlgorithms) {
            return cipherSuiteInfo.getDecompositionTLS();
        }
        return cipherSuiteInfo.getDecompositionX509();
    }
}
