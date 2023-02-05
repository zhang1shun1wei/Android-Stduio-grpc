package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

public abstract class DTLSProtocol {
    protected DTLSProtocol() {
    }

    /* access modifiers changed from: protected */
    public void processFinished(byte[] body, byte[] expected_verify_data) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        byte[] verify_data = TlsUtils.readFully(expected_verify_data.length, buf);
        TlsProtocol.assertEmpty(buf);
        if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data)) {
            throw new TlsFatalAlert((short) 40);
        }
    }

    protected static void applyMaxFragmentLengthExtension(DTLSRecordLayer recordLayer, short maxFragmentLength) throws IOException {
        if (maxFragmentLength < 0) {
            return;
        }
        if (!MaxFragmentLength.isValid(maxFragmentLength)) {
            throw new TlsFatalAlert((short) 80);
        }
        recordLayer.setPlaintextLimit(1 << (maxFragmentLength + 8));
    }

    protected static short evaluateMaxFragmentLengthExtension(boolean resumedSession, Hashtable clientExtensions, Hashtable serverExtensions, short alertDescription) throws IOException {
        short maxFragmentLength = TlsExtensionsUtils.getMaxFragmentLengthExtension(serverExtensions);
        if (maxFragmentLength < 0 || (MaxFragmentLength.isValid(maxFragmentLength) && (resumedSession || maxFragmentLength == TlsExtensionsUtils.getMaxFragmentLengthExtension(clientExtensions)))) {
            return maxFragmentLength;
        }
        throw new TlsFatalAlert(alertDescription);
    }

    protected static byte[] generateCertificate(TlsContext context, Certificate certificate, OutputStream endPointHash) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificate.encode(context, buf, endPointHash);
        return buf.toByteArray();
    }

    protected static byte[] generateSupplementalData(Vector supplementalData) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsProtocol.writeSupplementalData(buf, supplementalData);
        return buf.toByteArray();
    }

    protected static void sendCertificateMessage(TlsContext context, DTLSReliableHandshake handshake, Certificate certificate, OutputStream endPointHash) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        if (securityParameters.getLocalCertificate() != null) {
            throw new TlsFatalAlert((short) 80);
        }
        if (certificate == null) {
            certificate = Certificate.EMPTY_CHAIN;
        }
        handshake.sendMessage((short) 11, generateCertificate(context, certificate, endPointHash));
        securityParameters.localCertificate = certificate;
    }

    protected static int validateSelectedCipherSuite(int selectedCipherSuite, short alertDescription) throws IOException {
        switch (TlsUtils.getEncryptionAlgorithm(selectedCipherSuite)) {
            case -1:
            case 1:
            case 2:
                throw new TlsFatalAlert(alertDescription);
            case 0:
            default:
                return selectedCipherSuite;
        }
    }
}
