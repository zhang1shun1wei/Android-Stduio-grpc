package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import com.mi.car.jsse.easysec.jsse.BCSSLParameters;
import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import java.net.Socket;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

/* access modifiers changed from: package-private */
public class TransportData {
    private final BCExtendedSSLSession handshakeSession;
    private final BCSSLParameters parameters;

    static TransportData from(Socket socket) {
        SSLSocket sslSocket;
        BCSSLParameters parameters2;
        if (!(socket instanceof SSLSocket) || !socket.isConnected() || (parameters2 = SSLSocketUtil.importSSLParameters((sslSocket = (SSLSocket) socket))) == null) {
            return null;
        }
        return new TransportData(parameters2, SSLSocketUtil.importHandshakeSession(sslSocket));
    }

    static TransportData from(SSLEngine engine) {
        BCSSLParameters parameters2;
        if (engine == null || (parameters2 = SSLEngineUtil.importSSLParameters(engine)) == null) {
            return null;
        }
        return new TransportData(parameters2, SSLEngineUtil.importHandshakeSession(engine));
    }

    static BCAlgorithmConstraints getAlgorithmConstraints(TransportData transportData, boolean peerSigAlgs) {
        if (transportData == null) {
            return ProvAlgorithmConstraints.DEFAULT;
        }
        return transportData.getAlgorithmConstraints(peerSigAlgs);
    }

    static List<byte[]> getStatusResponses(TransportData transportData) {
        if (transportData == null) {
            return Collections.emptyList();
        }
        return transportData.getStatusResponses();
    }

    private TransportData(BCSSLParameters parameters2, BCExtendedSSLSession handshakeSession2) {
        this.parameters = parameters2;
        this.handshakeSession = handshakeSession2;
    }

    /* access modifiers changed from: package-private */
    public BCSSLParameters getParameters() {
        return this.parameters;
    }

    /* access modifiers changed from: package-private */
    public BCExtendedSSLSession getHandshakeSession() {
        return this.handshakeSession;
    }

    /* access modifiers changed from: package-private */
    public BCAlgorithmConstraints getAlgorithmConstraints(boolean peerSigAlgs) {
        String[] sigAlgsCert;
        BCAlgorithmConstraints configAlgorithmConstraints = this.parameters.getAlgorithmConstraints();
        if (ProvAlgorithmConstraints.DEFAULT == configAlgorithmConstraints) {
            configAlgorithmConstraints = null;
        }
        if (this.handshakeSession != null && JsseUtils.isTLSv12(this.handshakeSession.getProtocol())) {
            if (peerSigAlgs) {
                sigAlgsCert = this.handshakeSession.getPeerSupportedSignatureAlgorithmsBC();
            } else {
                sigAlgsCert = this.handshakeSession.getLocalSupportedSignatureAlgorithmsBC();
            }
            if (sigAlgsCert != null) {
                return new ProvAlgorithmConstraints(configAlgorithmConstraints, sigAlgsCert, true);
            }
        }
        return configAlgorithmConstraints == null ? ProvAlgorithmConstraints.DEFAULT : new ProvAlgorithmConstraints(configAlgorithmConstraints, true);
    }

    /* access modifiers changed from: package-private */
    public List<byte[]> getStatusResponses() {
        if (this.handshakeSession == null) {
            return Collections.emptyList();
        }
        return this.handshakeSession.getStatusResponses();
    }
}
