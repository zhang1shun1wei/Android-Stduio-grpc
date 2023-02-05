package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncryptor;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TlsPSKKeyExchange extends AbstractTlsKeyExchange {
    protected TlsAgreement agreement;
    protected TlsDHConfig dhConfig;
    protected TlsDHGroupVerifier dhGroupVerifier;
    protected TlsECConfig ecConfig;
    protected TlsSecret preMasterSecret;
    protected byte[] psk;
    protected TlsPSKIdentity pskIdentity;
    protected TlsPSKIdentityManager pskIdentityManager;
    protected byte[] psk_identity_hint;
    protected TlsCredentialedDecryptor serverCredentials;
    protected TlsEncryptor serverEncryptor;

    private static int checkKeyExchange(int keyExchange) {
        switch (keyExchange) {
            case 13:
            case 14:
            case 15:
            case 24:
                return keyExchange;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    public TlsPSKKeyExchange(int keyExchange, TlsPSKIdentity pskIdentity2, TlsDHGroupVerifier dhGroupVerifier2) {
        this(keyExchange, pskIdentity2, null, dhGroupVerifier2, null, null);
    }

    public TlsPSKKeyExchange(int keyExchange, TlsPSKIdentityManager pskIdentityManager2, TlsDHConfig dhConfig2, TlsECConfig ecConfig2) {
        this(keyExchange, null, pskIdentityManager2, null, dhConfig2, ecConfig2);
    }

    private TlsPSKKeyExchange(int keyExchange, TlsPSKIdentity pskIdentity2, TlsPSKIdentityManager pskIdentityManager2, TlsDHGroupVerifier dhGroupVerifier2, TlsDHConfig dhConfig2, TlsECConfig ecConfig2) {
        super(checkKeyExchange(keyExchange));
        this.psk_identity_hint = null;
        this.psk = null;
        this.serverCredentials = null;
        this.pskIdentity = pskIdentity2;
        this.pskIdentityManager = pskIdentityManager2;
        this.dhGroupVerifier = dhGroupVerifier2;
        this.dhConfig = dhConfig2;
        this.ecConfig = ecConfig2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void skipServerCredentials() throws IOException {
        if (this.keyExchange == 15) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processServerCredentials(TlsCredentials serverCredentials2) throws IOException {
        if (this.keyExchange != 15) {
            throw new TlsFatalAlert((short) 80);
        }
        this.serverCredentials = TlsUtils.requireDecryptorCredentials(serverCredentials2);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerCertificate(Certificate serverCertificate) throws IOException {
        if (this.keyExchange != 15) {
            throw new TlsFatalAlert((short) 10);
        }
        this.serverEncryptor = serverCertificate.getCertificateAt(0).createEncryptor(3);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public byte[] generateServerKeyExchange() throws IOException {
        this.psk_identity_hint = this.pskIdentityManager.getHint();
        if (this.psk_identity_hint == null && !requiresServerKeyExchange()) {
            return null;
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        if (this.psk_identity_hint == null) {
            TlsUtils.writeOpaque16(TlsUtils.EMPTY_BYTES, buf);
        } else {
            TlsUtils.writeOpaque16(this.psk_identity_hint, buf);
        }
        if (this.keyExchange == 14) {
            if (this.dhConfig == null) {
                throw new TlsFatalAlert((short) 80);
            }
            TlsDHUtils.writeDHConfig(this.dhConfig, buf);
            this.agreement = this.context.getCrypto().createDHDomain(this.dhConfig).createDH();
            generateEphemeralDH(buf);
        } else if (this.keyExchange == 24) {
            if (this.ecConfig == null) {
                throw new TlsFatalAlert((short) 80);
            }
            TlsECCUtils.writeECConfig(this.ecConfig, buf);
            this.agreement = this.context.getCrypto().createECDomain(this.ecConfig).createECDH();
            generateEphemeralECDH(buf);
        }
        return buf.toByteArray();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public boolean requiresServerKeyExchange() {
        switch (this.keyExchange) {
            case 14:
            case 24:
                return true;
            default:
                return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerKeyExchange(InputStream input) throws IOException {
        this.psk_identity_hint = TlsUtils.readOpaque16(input);
        if (this.keyExchange == 14) {
            this.dhConfig = TlsDHUtils.receiveDHConfig(this.context, this.dhGroupVerifier, input);
            byte[] y = TlsUtils.readOpaque16(input, 1);
            this.agreement = this.context.getCrypto().createDHDomain(this.dhConfig).createDH();
            processEphemeralDH(y);
        } else if (this.keyExchange == 24) {
            this.ecConfig = TlsECCUtils.receiveECDHConfig(this.context, input);
            byte[] point = TlsUtils.readOpaque8(input, 1);
            this.agreement = this.context.getCrypto().createECDomain(this.ecConfig).createECDH();
            processEphemeralECDH(point);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void generateClientKeyExchange(OutputStream output) throws IOException {
        if (this.psk_identity_hint == null) {
            this.pskIdentity.skipIdentityHint();
        } else {
            this.pskIdentity.notifyIdentityHint(this.psk_identity_hint);
        }
        byte[] psk_identity = this.pskIdentity.getPSKIdentity();
        if (psk_identity == null) {
            throw new TlsFatalAlert((short) 80);
        }
        this.psk = this.pskIdentity.getPSK();
        if (this.psk == null) {
            throw new TlsFatalAlert((short) 80);
        }
        TlsUtils.writeOpaque16(psk_identity, output);
        this.context.getSecurityParametersHandshake().pskIdentity = Arrays.clone(psk_identity);
        if (this.keyExchange == 14) {
            generateEphemeralDH(output);
        } else if (this.keyExchange == 24) {
            generateEphemeralECDH(output);
        } else if (this.keyExchange == 15) {
            this.preMasterSecret = TlsUtils.generateEncryptedPreMasterSecret(this.context, this.serverEncryptor, output);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processClientKeyExchange(InputStream input) throws IOException {
        byte[] psk_identity = TlsUtils.readOpaque16(input);
        this.psk = this.pskIdentityManager.getPSK(psk_identity);
        if (this.psk == null) {
            throw new TlsFatalAlert(AlertDescription.unknown_psk_identity);
        }
        this.context.getSecurityParametersHandshake().pskIdentity = psk_identity;
        if (this.keyExchange == 14) {
            processEphemeralDH(TlsUtils.readOpaque16(input, 1));
        } else if (this.keyExchange == 24) {
            processEphemeralECDH(TlsUtils.readOpaque8(input, 1));
        } else if (this.keyExchange == 15) {
            this.preMasterSecret = this.serverCredentials.decrypt(new TlsCryptoParameters(this.context), TlsUtils.readEncryptedPMS(this.context, input));
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public TlsSecret generatePreMasterSecret() throws IOException {
        byte[] other_secret = generateOtherSecret(this.psk.length);
        ByteArrayOutputStream buf = new ByteArrayOutputStream(other_secret.length + 4 + this.psk.length);
        TlsUtils.writeOpaque16(other_secret, buf);
        TlsUtils.writeOpaque16(this.psk, buf);
        Arrays.fill(this.psk, (byte) 0);
        this.psk = null;
        return this.context.getCrypto().createSecret(buf.toByteArray());
    }

    /* access modifiers changed from: protected */
    public void generateEphemeralDH(OutputStream output) throws IOException {
        TlsUtils.writeOpaque16(this.agreement.generateEphemeral(), output);
    }

    /* access modifiers changed from: protected */
    public void generateEphemeralECDH(OutputStream output) throws IOException {
        TlsUtils.writeOpaque8(this.agreement.generateEphemeral(), output);
    }

    /* access modifiers changed from: protected */
    public byte[] generateOtherSecret(int pskLength) throws IOException {
        if (this.keyExchange == 13) {
            return new byte[pskLength];
        }
        if ((this.keyExchange == 14 || this.keyExchange == 24) && this.agreement != null) {
            return this.agreement.calculateSecret().extract();
        }
        if (this.keyExchange == 15 && this.preMasterSecret != null) {
            return this.preMasterSecret.extract();
        }
        throw new TlsFatalAlert((short) 80);
    }

    /* access modifiers changed from: protected */
    public void processEphemeralDH(byte[] y) throws IOException {
        this.agreement.receivePeerValue(y);
    }

    /* access modifiers changed from: protected */
    public void processEphemeralECDH(byte[] point) throws IOException {
        TlsECCUtils.checkPointEncoding(this.ecConfig.getNamedGroup(), point);
        this.agreement.receivePeerValue(point);
    }
}
