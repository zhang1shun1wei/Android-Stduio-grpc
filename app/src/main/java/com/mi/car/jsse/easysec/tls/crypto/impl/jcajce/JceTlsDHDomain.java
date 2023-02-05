package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.TlsDHUtils;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.DHGroup;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoException;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHDomain;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class JceTlsDHDomain implements TlsDHDomain {
    protected final JcaTlsCrypto crypto;
    protected final TlsDHConfig dhConfig;
    protected final DHParameterSpec dhSpec;

    private static byte[] encodeValue(DHParameterSpec dh, boolean padded, BigInteger x) {
        if (padded) {
            return BigIntegers.asUnsignedByteArray(getValueLength(dh), x);
        }
        return BigIntegers.asUnsignedByteArray(x);
    }

    private static int getValueLength(DHParameterSpec dh) {
        return (dh.getP().bitLength() + 7) / 8;
    }

    public static JceTlsSecret calculateDHAgreement(JcaTlsCrypto crypto2, DHPrivateKey privateKey, DHPublicKey publicKey, boolean padded) throws IOException {
        try {
            byte[] secret = crypto2.calculateKeyAgreement("DiffieHellman", privateKey, publicKey, "TlsPremasterSecret");
            if (padded) {
                int length = getValueLength(privateKey.getParams());
                byte[] tmp = new byte[length];
                System.arraycopy(secret, 0, tmp, length - secret.length, secret.length);
                Arrays.fill(secret, (byte) 0);
                secret = tmp;
            }
            return crypto2.adoptLocalSecret(secret);
        } catch (GeneralSecurityException e) {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    public JceTlsDHDomain(JcaTlsCrypto crypto2, TlsDHConfig dhConfig2) {
        DHParameterSpec spec;
        DHGroup dhGroup = TlsDHUtils.getDHGroup(dhConfig2);
        if (dhGroup == null || (spec = DHUtil.getDHParameterSpec(crypto2, dhGroup)) == null) {
            throw new IllegalArgumentException("No DH configuration provided");
        }
        this.crypto = crypto2;
        this.dhConfig = dhConfig2;
        this.dhSpec = spec;
    }

    public JceTlsSecret calculateDHAgreement(DHPrivateKey privateKey, DHPublicKey publicKey) throws IOException {
        return calculateDHAgreement(this.crypto, privateKey, publicKey, this.dhConfig.isPadded());
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsDHDomain
    public TlsAgreement createDH() {
        return new JceTlsDH(this);
    }

    public BigInteger decodeParameter(byte[] encoding) throws IOException {
        if (!this.dhConfig.isPadded() || getValueLength(this.dhSpec) == encoding.length) {
            return new BigInteger(1, encoding);
        }
        throw new TlsFatalAlert((short) 47);
    }

    public DHPublicKey decodePublicKey(byte[] encoding) throws IOException {
        try {
            return (DHPublicKey) this.crypto.getHelper().createKeyFactory("DiffieHellman").generatePublic(DHUtil.createPublicKeySpec(decodeParameter(encoding), this.dhSpec));
        } catch (IOException e) {
            throw e;
        } catch (Exception e2) {
            throw new TlsFatalAlert((short) 40, (Throwable) e2);
        }
    }

    public byte[] encodeParameter(BigInteger x) throws IOException {
        return encodeValue(this.dhSpec, this.dhConfig.isPadded(), x);
    }

    public byte[] encodePublicKey(DHPublicKey publicKey) throws IOException {
        return encodeValue(this.dhSpec, true, publicKey.getY());
    }

    public KeyPair generateKeyPair() throws IOException {
        try {
            KeyPairGenerator keyPairGenerator = this.crypto.getHelper().createKeyPairGenerator("DiffieHellman");
            keyPairGenerator.initialize(this.dhSpec, this.crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new TlsCryptoException("unable to create key pair", e);
        }
    }
}
