package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRP6Client;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRP6Server;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRPConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.io.TeeInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

public class TlsSRPKeyExchange extends AbstractTlsKeyExchange {
    protected TlsCertificate serverCertificate = null;
    protected TlsCredentialedSigner serverCredentials = null;
    protected TlsSRP6Client srpClient = null;
    protected TlsSRPConfigVerifier srpConfigVerifier;
    protected TlsSRPIdentity srpIdentity;
    protected TlsSRPLoginParameters srpLoginParameters;
    protected BigInteger srpPeerCredentials = null;
    protected byte[] srpSalt = null;
    protected TlsSRP6Server srpServer = null;

    private static int checkKeyExchange(int keyExchange) {
        switch (keyExchange) {
            case 21:
            case 22:
            case 23:
                return keyExchange;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    public TlsSRPKeyExchange(int keyExchange, TlsSRPIdentity srpIdentity2, TlsSRPConfigVerifier srpConfigVerifier2) {
        super(checkKeyExchange(keyExchange));
        this.srpIdentity = srpIdentity2;
        this.srpConfigVerifier = srpConfigVerifier2;
    }

    public TlsSRPKeyExchange(int keyExchange, TlsSRPLoginParameters srpLoginParameters2) {
        super(checkKeyExchange(keyExchange));
        this.srpLoginParameters = srpLoginParameters2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void skipServerCredentials() throws IOException {
        if (this.keyExchange != 21) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processServerCredentials(TlsCredentials serverCredentials2) throws IOException {
        if (this.keyExchange == 21) {
            throw new TlsFatalAlert((short) 80);
        }
        this.serverCredentials = TlsUtils.requireSignerCredentials(serverCredentials2);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerCertificate(Certificate serverCertificate2) throws IOException {
        if (this.keyExchange == 21) {
            throw new TlsFatalAlert((short) 80);
        }
        this.serverCertificate = serverCertificate2.getCertificateAt(0);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public boolean requiresServerKeyExchange() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public byte[] generateServerKeyExchange() throws IOException {
        TlsSRPConfig config = this.srpLoginParameters.getConfig();
        this.srpServer = this.context.getCrypto().createSRP6Server(config, this.srpLoginParameters.getVerifier());
        BigInteger B = this.srpServer.generateServerCredentials();
        BigInteger[] ng = config.getExplicitNG();
        ServerSRPParams srpParams = new ServerSRPParams(ng[0], ng[1], this.srpLoginParameters.getSalt(), B);
        DigestInputBuffer digestBuffer = new DigestInputBuffer();
        srpParams.encode(digestBuffer);
        if (this.serverCredentials != null) {
            TlsUtils.generateServerKeyExchangeSignature(this.context, this.serverCredentials, null, digestBuffer);
        }
        return digestBuffer.toByteArray();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processServerKeyExchange(InputStream input) throws IOException {
        DigestInputBuffer digestBuffer = null;
        InputStream teeIn = input;
        if (this.keyExchange != 21) {
            digestBuffer = new DigestInputBuffer();
            teeIn = new TeeInputStream(input, digestBuffer);
        }
        ServerSRPParams srpParams = ServerSRPParams.parse(teeIn);
        if (digestBuffer != null) {
            TlsUtils.verifyServerKeyExchangeSignature(this.context, input, this.serverCertificate, null, digestBuffer);
        }
        TlsSRPConfig config = new TlsSRPConfig();
        config.setExplicitNG(new BigInteger[]{srpParams.getN(), srpParams.getG()});
        if (!this.srpConfigVerifier.accept(config)) {
            throw new TlsFatalAlert((short) 71);
        }
        this.srpSalt = srpParams.getS();
        this.srpPeerCredentials = validatePublicValue(srpParams.getN(), srpParams.getB());
        this.srpClient = this.context.getCrypto().createSRP6Client(config);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public void generateClientKeyExchange(OutputStream output) throws IOException {
        byte[] identity = this.srpIdentity.getSRPIdentity();
        TlsSRPUtils.writeSRPParameter(this.srpClient.generateClientCredentials(this.srpSalt, identity, this.srpIdentity.getSRPPassword()), output);
        this.context.getSecurityParametersHandshake().srpIdentity = Arrays.clone(identity);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchange
    public void processClientKeyExchange(InputStream input) throws IOException {
        this.srpPeerCredentials = validatePublicValue(this.srpLoginParameters.getConfig().getExplicitNG()[0], TlsSRPUtils.readSRPParameter(input));
        this.context.getSecurityParametersHandshake().srpIdentity = Arrays.clone(this.srpLoginParameters.getIdentity());
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchange
    public TlsSecret generatePreMasterSecret() throws IOException {
        BigInteger S;
        if (this.srpServer != null) {
            S = this.srpServer.calculateSecret(this.srpPeerCredentials);
        } else {
            S = this.srpClient.calculateSecret(this.srpPeerCredentials);
        }
        return this.context.getCrypto().createSecret(BigIntegers.asUnsignedByteArray(S));
    }

    protected static BigInteger validatePublicValue(BigInteger N, BigInteger val) throws IOException {
        BigInteger val2 = val.mod(N);
        if (!val2.equals(BigInteger.ZERO)) {
            return val2;
        }
        throw new TlsFatalAlert((short) 47);
    }
}
