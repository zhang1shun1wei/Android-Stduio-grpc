package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.MessageEncryptor;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Vector;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2mField;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GoppaCode;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.Permutation;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import java.security.SecureRandom;

public class McElieceCipher implements MessageEncryptor {
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.1";
    public int cipherTextSize;
    private boolean forEncryption;
    private int k;
    private McElieceKeyParameters key;
    public int maxPlainTextSize;
    private int n;
    private SecureRandom sr;
    private int t;

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageEncryptor
    public void init(boolean forEncryption2, CipherParameters param) {
        this.forEncryption = forEncryption2;
        if (!forEncryption2) {
            this.key = (McEliecePrivateKeyParameters) param;
            initCipherDecrypt((McEliecePrivateKeyParameters) this.key);
        } else if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.sr = rParam.getRandom();
            this.key = (McEliecePublicKeyParameters) rParam.getParameters();
            initCipherEncrypt((McEliecePublicKeyParameters) this.key);
        } else {
            this.sr = CryptoServicesRegistrar.getSecureRandom();
            this.key = (McEliecePublicKeyParameters) param;
            initCipherEncrypt((McEliecePublicKeyParameters) this.key);
        }
    }

    public int getKeySize(McElieceKeyParameters key2) {
        if (key2 instanceof McEliecePublicKeyParameters) {
            return ((McEliecePublicKeyParameters) key2).getN();
        }
        if (key2 instanceof McEliecePrivateKeyParameters) {
            return ((McEliecePrivateKeyParameters) key2).getN();
        }
        throw new IllegalArgumentException("unsupported type");
    }

    private void initCipherEncrypt(McEliecePublicKeyParameters pubKey) {
        this.n = pubKey.getN();
        this.k = pubKey.getK();
        this.t = pubKey.getT();
        this.cipherTextSize = this.n >> 3;
        this.maxPlainTextSize = this.k >> 3;
    }

    private void initCipherDecrypt(McEliecePrivateKeyParameters privKey) {
        this.n = privKey.getN();
        this.k = privKey.getK();
        this.maxPlainTextSize = this.k >> 3;
        this.cipherTextSize = this.n >> 3;
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageEncryptor
    public byte[] messageEncrypt(byte[] input) {
        if (!this.forEncryption) {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        GF2Vector m = computeMessageRepresentative(input);
        return ((GF2Vector) ((McEliecePublicKeyParameters) this.key).getG().leftMultiply(m).add(new GF2Vector(this.n, this.t, this.sr))).getEncoded();
    }

    private GF2Vector computeMessageRepresentative(byte[] input) {
        int i;
        int i2 = this.maxPlainTextSize;
        if ((this.k & 7) != 0) {
            i = 1;
        } else {
            i = 0;
        }
        byte[] data = new byte[(i + i2)];
        System.arraycopy(input, 0, data, 0, input.length);
        data[input.length] = 1;
        return GF2Vector.OS2VP(this.k, data);
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageEncryptor
    public byte[] messageDecrypt(byte[] input) throws InvalidCipherTextException {
        if (this.forEncryption) {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        GF2Vector vec = GF2Vector.OS2VP(this.n, input);
        McEliecePrivateKeyParameters privKey = (McEliecePrivateKeyParameters) this.key;
        GF2mField field = privKey.getField();
        PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
        GF2Matrix sInv = privKey.getSInv();
        Permutation p1 = privKey.getP1();
        Permutation p2 = privKey.getP2();
        GF2Matrix h = privKey.getH();
        PolynomialGF2mSmallM[] qInv = privKey.getQInv();
        Permutation p = p1.rightMultiply(p2);
        GF2Vector cPInv = (GF2Vector) vec.multiply(p.computeInverse());
        GF2Vector z = GoppaCode.syndromeDecode((GF2Vector) h.rightMultiply(cPInv), field, gp, qInv);
        GF2Vector z2 = (GF2Vector) z.multiply(p);
        return computeMessage((GF2Vector) sInv.leftMultiply(((GF2Vector) ((GF2Vector) cPInv.add(z)).multiply(p1)).extractRightVector(this.k)));
    }

    private byte[] computeMessage(GF2Vector mr) throws InvalidCipherTextException {
        byte[] mrBytes = mr.getEncoded();
        int index = mrBytes.length - 1;
        while (index >= 0 && mrBytes[index] == 0) {
            index--;
        }
        if (index < 0 || mrBytes[index] != 1) {
            throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
        }
        byte[] mBytes = new byte[index];
        System.arraycopy(mrBytes, 0, mBytes, 0, index);
        return mBytes;
    }
}
