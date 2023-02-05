package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BasicAgreement;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DerivationFunction;
import com.mi.car.jsse.easysec.crypto.EphemeralKeyPair;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.KeyParser;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.generators.EphemeralKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.IESParameters;
import com.mi.car.jsse.easysec.crypto.params.IESWithCipherParameters;
import com.mi.car.jsse.easysec.crypto.params.KDFParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class IESEngine {
    private byte[] IV;
    byte[] V;
    BasicAgreement agree;
    BufferedBlockCipher cipher;
    boolean forEncryption;
    DerivationFunction kdf;
    private EphemeralKeyPairGenerator keyPairGenerator;
    private KeyParser keyParser;
    Mac mac;
    byte[] macBuf;
    IESParameters param;
    CipherParameters privParam;
    CipherParameters pubParam;

    public IESEngine(BasicAgreement agree2, DerivationFunction kdf2, Mac mac2) {
        this.agree = agree2;
        this.kdf = kdf2;
        this.mac = mac2;
        this.macBuf = new byte[mac2.getMacSize()];
        this.cipher = null;
    }

    public IESEngine(BasicAgreement agree2, DerivationFunction kdf2, Mac mac2, BufferedBlockCipher cipher2) {
        this.agree = agree2;
        this.kdf = kdf2;
        this.mac = mac2;
        this.macBuf = new byte[mac2.getMacSize()];
        this.cipher = cipher2;
    }

    public void init(boolean forEncryption2, CipherParameters privParam2, CipherParameters pubParam2, CipherParameters params) {
        this.forEncryption = forEncryption2;
        this.privParam = privParam2;
        this.pubParam = pubParam2;
        this.V = new byte[0];
        extractParams(params);
    }

    public void init(AsymmetricKeyParameter publicKey, CipherParameters params, EphemeralKeyPairGenerator ephemeralKeyPairGenerator) {
        this.forEncryption = true;
        this.pubParam = publicKey;
        this.keyPairGenerator = ephemeralKeyPairGenerator;
        extractParams(params);
    }

    public void init(AsymmetricKeyParameter privateKey, CipherParameters params, KeyParser publicKeyParser) {
        this.forEncryption = false;
        this.privParam = privateKey;
        this.keyParser = publicKeyParser;
        extractParams(params);
    }

    private void extractParams(CipherParameters params) {
        if (params instanceof ParametersWithIV) {
            this.IV = ((ParametersWithIV) params).getIV();
            this.param = (IESParameters) ((ParametersWithIV) params).getParameters();
            return;
        }
        this.IV = null;
        this.param = (IESParameters) params;
    }

    public BufferedBlockCipher getCipher() {
        return this.cipher;
    }

    public Mac getMac() {
        return this.mac;
    }

    private byte[] encryptBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        byte[] K2;
        byte[] C;
        int len;
        if (this.cipher == null) {
            byte[] K1 = new byte[inLen];
            K2 = new byte[(this.param.getMacKeySize() / 8)];
            byte[] K = new byte[(K1.length + K2.length)];
            this.kdf.generateBytes(K, 0, K.length);
            if (this.V.length != 0) {
                System.arraycopy(K, 0, K2, 0, K2.length);
                System.arraycopy(K, K2.length, K1, 0, K1.length);
            } else {
                System.arraycopy(K, 0, K1, 0, K1.length);
                System.arraycopy(K, inLen, K2, 0, K2.length);
            }
            C = new byte[inLen];
            for (int i = 0; i != inLen; i++) {
                C[i] = (byte) (in[inOff + i] ^ K1[i]);
            }
            len = inLen;
        } else {
            byte[] K12 = new byte[(((IESWithCipherParameters) this.param).getCipherKeySize() / 8)];
            K2 = new byte[(this.param.getMacKeySize() / 8)];
            byte[] K3 = new byte[(K12.length + K2.length)];
            this.kdf.generateBytes(K3, 0, K3.length);
            System.arraycopy(K3, 0, K12, 0, K12.length);
            System.arraycopy(K3, K12.length, K2, 0, K2.length);
            if (this.IV != null) {
                this.cipher.init(true, new ParametersWithIV(new KeyParameter(K12), this.IV));
            } else {
                this.cipher.init(true, new KeyParameter(K12));
            }
            C = new byte[this.cipher.getOutputSize(inLen)];
            int len2 = this.cipher.processBytes(in, inOff, inLen, C, 0);
            len = len2 + this.cipher.doFinal(C, len2);
        }
        byte[] P2 = this.param.getEncodingV();
        byte[] L2 = null;
        if (this.V.length != 0) {
            L2 = getLengthTag(P2);
        }
        byte[] T = new byte[this.mac.getMacSize()];
        this.mac.init(new KeyParameter(K2));
        this.mac.update(C, 0, C.length);
        if (P2 != null) {
            this.mac.update(P2, 0, P2.length);
        }
        if (this.V.length != 0) {
            this.mac.update(L2, 0, L2.length);
        }
        this.mac.doFinal(T, 0);
        byte[] Output = new byte[(this.V.length + len + T.length)];
        System.arraycopy(this.V, 0, Output, 0, this.V.length);
        System.arraycopy(C, 0, Output, this.V.length, len);
        System.arraycopy(T, 0, Output, this.V.length + len, T.length);
        return Output;
    }

    private byte[] decryptBlock(byte[] in_enc, int inOff, int inLen) throws InvalidCipherTextException {
        byte[] K2;
        byte[] M;
        int len = 0;
        if (inLen < this.V.length + this.mac.getMacSize()) {
            throw new InvalidCipherTextException("Length of input must be greater than the MAC and V combined");
        }
        if (this.cipher == null) {
            byte[] K1 = new byte[((inLen - this.V.length) - this.mac.getMacSize())];
            K2 = new byte[(this.param.getMacKeySize() / 8)];
            byte[] K = new byte[(K1.length + K2.length)];
            this.kdf.generateBytes(K, 0, K.length);
            if (this.V.length != 0) {
                System.arraycopy(K, 0, K2, 0, K2.length);
                System.arraycopy(K, K2.length, K1, 0, K1.length);
            } else {
                System.arraycopy(K, 0, K1, 0, K1.length);
                System.arraycopy(K, K1.length, K2, 0, K2.length);
            }
            M = new byte[K1.length];
            for (int i = 0; i != K1.length; i++) {
                M[i] = (byte) (in_enc[(this.V.length + inOff) + i] ^ K1[i]);
            }
        } else {
            byte[] K12 = new byte[(((IESWithCipherParameters) this.param).getCipherKeySize() / 8)];
            K2 = new byte[(this.param.getMacKeySize() / 8)];
            byte[] K3 = new byte[(K12.length + K2.length)];
            this.kdf.generateBytes(K3, 0, K3.length);
            System.arraycopy(K3, 0, K12, 0, K12.length);
            System.arraycopy(K3, K12.length, K2, 0, K2.length);
            CipherParameters cp = new KeyParameter(K12);
            if (this.IV != null) {
                cp = new ParametersWithIV(cp, this.IV);
            }
            this.cipher.init(false, cp);
            M = new byte[this.cipher.getOutputSize((inLen - this.V.length) - this.mac.getMacSize())];
            len = this.cipher.processBytes(in_enc, inOff + this.V.length, (inLen - this.V.length) - this.mac.getMacSize(), M, 0);
        }
        byte[] P2 = this.param.getEncodingV();
        byte[] L2 = null;
        if (this.V.length != 0) {
            L2 = getLengthTag(P2);
        }
        int end = inOff + inLen;
        byte[] T1 = Arrays.copyOfRange(in_enc, end - this.mac.getMacSize(), end);
        byte[] T2 = new byte[T1.length];
        this.mac.init(new KeyParameter(K2));
        this.mac.update(in_enc, this.V.length + inOff, (inLen - this.V.length) - T2.length);
        if (P2 != null) {
            this.mac.update(P2, 0, P2.length);
        }
        if (this.V.length != 0) {
            this.mac.update(L2, 0, L2.length);
        }
        this.mac.doFinal(T2, 0);
        if (Arrays.constantTimeAreEqual(T1, T2)) {
            return this.cipher == null ? M : Arrays.copyOfRange(M, 0, len + this.cipher.doFinal(M, len));
        }
        throw new InvalidCipherTextException("invalid MAC");
    }

    public byte[] processBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        byte[] decryptBlock;
        if (this.forEncryption) {
            if (this.keyPairGenerator != null) {
                EphemeralKeyPair ephKeyPair = this.keyPairGenerator.generate();
                this.privParam = ephKeyPair.getKeyPair().getPrivate();
                this.V = ephKeyPair.getEncodedPublicKey();
            }
        } else if (this.keyParser != null) {
            ByteArrayInputStream bIn = new ByteArrayInputStream(in, inOff, inLen);
            try {
                this.pubParam = this.keyParser.readKey(bIn);
                this.V = Arrays.copyOfRange(in, inOff, inOff + (inLen - bIn.available()));
            } catch (IOException e) {
                throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
            } catch (IllegalArgumentException e2) {
                throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e2.getMessage(), e2);
            }
        }
        this.agree.init(this.privParam);
        byte[] Z = BigIntegers.asUnsignedByteArray(this.agree.getFieldSize(), this.agree.calculateAgreement(this.pubParam));
        if (this.V.length != 0) {
            byte[] VZ = Arrays.concatenate(this.V, Z);
            Arrays.fill(Z, (byte) 0);
            Z = VZ;
        }
        try {
            this.kdf.init(new KDFParameters(Z, this.param.getDerivationV()));
            if (this.forEncryption) {
                decryptBlock = encryptBlock(in, inOff, inLen);
            } else {
                decryptBlock = decryptBlock(in, inOff, inLen);
            }
            return decryptBlock;
        } finally {
            Arrays.fill(Z, (byte) 0);
        }
    }

    /* access modifiers changed from: protected */
    public byte[] getLengthTag(byte[] p2) {
        byte[] L2 = new byte[8];
        if (p2 != null) {
            Pack.longToBigEndian(((long) p2.length) * 8, L2, 0);
        }
        return L2;
    }
}
