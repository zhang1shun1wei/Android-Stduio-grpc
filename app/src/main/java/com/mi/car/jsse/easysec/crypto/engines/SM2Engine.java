package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.digests.SM3Digest;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECMultiplier;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.ec.FixedPointCombMultiplier;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.Memoable;
import com.mi.car.jsse.easysec.util.Pack;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SM2Engine {
    private int curveLength;
    private final Digest digest;
    private ECKeyParameters ecKey;
    private ECDomainParameters ecParams;
    private boolean forEncryption;
    private final Mode mode;
    private SecureRandom random;

    public enum Mode {
        C1C2C3,
        C1C3C2
    }

    public SM2Engine() {
        this(new SM3Digest());
    }

    public SM2Engine(Mode mode2) {
        this(new SM3Digest(), mode2);
    }

    public SM2Engine(Digest digest2) {
        this(digest2, Mode.C1C2C3);
    }

    public SM2Engine(Digest digest2, Mode mode2) {
        if (mode2 == null) {
            throw new IllegalArgumentException("mode cannot be NULL");
        }
        this.digest = digest2;
        this.mode = mode2;
    }

    public void init(boolean forEncryption2, CipherParameters param) {
        this.forEncryption = forEncryption2;
        if (forEncryption2) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.ecKey = (ECKeyParameters) rParam.getParameters();
            this.ecParams = this.ecKey.getParameters();
            if (((ECPublicKeyParameters) this.ecKey).getQ().multiply(this.ecParams.getH()).isInfinity()) {
                throw new IllegalArgumentException("invalid key: [h]Q at infinity");
            }
            this.random = rParam.getRandom();
        } else {
            this.ecKey = (ECKeyParameters) param;
            this.ecParams = this.ecKey.getParameters();
        }
        this.curveLength = (this.ecParams.getCurve().getFieldSize() + 7) / 8;
    }

    public byte[] processBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        if (this.forEncryption) {
            return encrypt(in, inOff, inLen);
        }
        return decrypt(in, inOff, inLen);
    }

    public int getOutputSize(int inputLen) {
        return (this.curveLength * 2) + 1 + inputLen + this.digest.getDigestSize();
    }

    /* access modifiers changed from: protected */
    public ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    private byte[] encrypt(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        byte[] c1;
        ECPoint kPB;
        byte[] c2 = new byte[inLen];
        System.arraycopy(in, inOff, c2, 0, c2.length);
        ECMultiplier multiplier = createBasePointMultiplier();
        do {
            BigInteger k = nextK();
            c1 = multiplier.multiply(this.ecParams.getG(), k).normalize().getEncoded(false);
            kPB = ((ECPublicKeyParameters) this.ecKey).getQ().multiply(k).normalize();
            kdf(this.digest, kPB, c2);
        } while (notEncrypted(c2, in, inOff));
        byte[] c3 = new byte[this.digest.getDigestSize()];
        addFieldElement(this.digest, kPB.getAffineXCoord());
        this.digest.update(in, inOff, inLen);
        addFieldElement(this.digest, kPB.getAffineYCoord());
        this.digest.doFinal(c3, 0);
        switch (this.mode) {
            case C1C3C2:
                return Arrays.concatenate(c1, c3, c2);
            default:
                return Arrays.concatenate(c1, c2, c3);
        }
    }

    private byte[] decrypt(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        byte[] c1 = new byte[((this.curveLength * 2) + 1)];
        System.arraycopy(in, inOff, c1, 0, c1.length);
        ECPoint c1P = this.ecParams.getCurve().decodePoint(c1);
        if (c1P.multiply(this.ecParams.getH()).isInfinity()) {
            throw new InvalidCipherTextException("[h]C1 at infinity");
        }
        ECPoint c1P2 = c1P.multiply(((ECPrivateKeyParameters) this.ecKey).getD()).normalize();
        int digestSize = this.digest.getDigestSize();
        byte[] c2 = new byte[((inLen - c1.length) - digestSize)];
        if (this.mode == Mode.C1C3C2) {
            System.arraycopy(in, c1.length + inOff + digestSize, c2, 0, c2.length);
        } else {
            System.arraycopy(in, c1.length + inOff, c2, 0, c2.length);
        }
        kdf(this.digest, c1P2, c2);
        byte[] c3 = new byte[this.digest.getDigestSize()];
        addFieldElement(this.digest, c1P2.getAffineXCoord());
        this.digest.update(c2, 0, c2.length);
        addFieldElement(this.digest, c1P2.getAffineYCoord());
        this.digest.doFinal(c3, 0);
        int check = 0;
        if (this.mode == Mode.C1C3C2) {
            for (int i = 0; i != c3.length; i++) {
                check |= c3[i] ^ in[(c1.length + inOff) + i];
            }
        } else {
            for (int i2 = 0; i2 != c3.length; i2++) {
                check |= c3[i2] ^ in[((c1.length + inOff) + c2.length) + i2];
            }
        }
        Arrays.fill(c1, (byte) 0);
        Arrays.fill(c3, (byte) 0);
        if (check == 0) {
            return c2;
        }
        Arrays.fill(c2, (byte) 0);
        throw new InvalidCipherTextException("invalid cipher text");
    }

    private boolean notEncrypted(byte[] encData, byte[] in, int inOff) {
        for (int i = 0; i != encData.length; i++) {
            if (encData[i] != in[inOff + i]) {
                return false;
            }
        }
        return true;
    }

    private void kdf(Digest digest2, ECPoint c1, byte[] encData) {
        int digestSize = digest2.getDigestSize();
        byte[] buf = new byte[Math.max(4, digestSize)];
        int off = 0;
        Memoable memo = null;
        Memoable copy = null;
        if (digest2 instanceof Memoable) {
            addFieldElement(digest2, c1.getAffineXCoord());
            addFieldElement(digest2, c1.getAffineYCoord());
            memo = (Memoable) digest2;
            copy = memo.copy();
        }
        int ct = 0;
        while (off < encData.length) {
            if (memo != null) {
                memo.reset(copy);
            } else {
                addFieldElement(digest2, c1.getAffineXCoord());
                addFieldElement(digest2, c1.getAffineYCoord());
            }
            ct++;
            Pack.intToBigEndian(ct, buf, 0);
            digest2.update(buf, 0, 4);
            digest2.doFinal(buf, 0);
            int xorLen = Math.min(digestSize, encData.length - off);
            xor(encData, buf, off, xorLen);
            off += xorLen;
        }
    }

    private void xor(byte[] data, byte[] kdfOut, int dOff, int dRemaining) {
        for (int i = 0; i != dRemaining; i++) {
            int i2 = dOff + i;
            data[i2] = (byte) (data[i2] ^ kdfOut[i]);
        }
    }

    private BigInteger nextK() {
        int qBitLength = this.ecParams.getN().bitLength();
        while (true) {
            BigInteger k = BigIntegers.createRandomBigInteger(qBitLength, this.random);
            if (!k.equals(BigIntegers.ZERO) && k.compareTo(this.ecParams.getN()) < 0) {
                return k;
            }
        }
    }

    private void addFieldElement(Digest digest2, ECFieldElement v) {
        byte[] p = BigIntegers.asUnsignedByteArray(this.curveLength, v.toBigInteger());
        digest2.update(p, 0, p.length);
    }
}
