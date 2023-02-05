package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.SignerWithRecovery;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithSalt;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public class ISO9796d2PSSSigner implements SignerWithRecovery {
    public static final int TRAILER_IMPLICIT = 188;
    public static final int TRAILER_RIPEMD128 = 13004;
    public static final int TRAILER_RIPEMD160 = 12748;
    public static final int TRAILER_SHA1 = 13260;
    public static final int TRAILER_SHA256 = 13516;
    public static final int TRAILER_SHA384 = 14028;
    public static final int TRAILER_SHA512 = 13772;
    public static final int TRAILER_WHIRLPOOL = 14284;
    private byte[] block;
    private AsymmetricBlockCipher cipher;
    private Digest digest;
    private boolean fullMessage;
    private int hLen;
    private int keyBits;
    private byte[] mBuf;
    private int messageLength;
    private byte[] preBlock;
    private int preMStart;
    private byte[] preSig;
    private int preTLength;
    private SecureRandom random;
    private byte[] recoveredMessage;
    private int saltLength;
    private byte[] standardSalt;
    private int trailer;

    public ISO9796d2PSSSigner(AsymmetricBlockCipher cipher2, Digest digest2, int saltLength2, boolean implicit) {
        this.cipher = cipher2;
        this.digest = digest2;
        this.hLen = digest2.getDigestSize();
        this.saltLength = saltLength2;
        if (implicit) {
            this.trailer = 188;
            return;
        }
        Integer trailerObj = ISOTrailers.getTrailer(digest2);
        if (trailerObj != null) {
            this.trailer = trailerObj.intValue();
            return;
        }
        throw new IllegalArgumentException("no valid trailer for digest: " + digest2.getAlgorithmName());
    }

    public ISO9796d2PSSSigner(AsymmetricBlockCipher cipher2, Digest digest2, int saltLength2) {
        this(cipher2, digest2, saltLength2, false);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void init(boolean forSigning, CipherParameters param) {
        RSAKeyParameters kParam;
        int lengthOfSalt = this.saltLength;
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom p = (ParametersWithRandom) param;
            kParam = (RSAKeyParameters) p.getParameters();
            if (forSigning) {
                this.random = p.getRandom();
            }
        } else if (param instanceof ParametersWithSalt) {
            ParametersWithSalt p2 = (ParametersWithSalt) param;
            kParam = (RSAKeyParameters) p2.getParameters();
            this.standardSalt = p2.getSalt();
            lengthOfSalt = this.standardSalt.length;
            if (this.standardSalt.length != this.saltLength) {
                throw new IllegalArgumentException("Fixed salt is of wrong length");
            }
        } else {
            kParam = (RSAKeyParameters) param;
            if (forSigning) {
                this.random = CryptoServicesRegistrar.getSecureRandom();
            }
        }
        this.cipher.init(forSigning, kParam);
        this.keyBits = kParam.getModulus().bitLength();
        this.block = new byte[((this.keyBits + 7) / 8)];
        if (this.trailer == 188) {
            this.mBuf = new byte[((((this.block.length - this.digest.getDigestSize()) - lengthOfSalt) - 1) - 1)];
        } else {
            this.mBuf = new byte[((((this.block.length - this.digest.getDigestSize()) - lengthOfSalt) - 1) - 2)];
        }
        reset();
    }

    private boolean isSameAs(byte[] a, byte[] b) {
        boolean isOkay = true;
        if (this.messageLength != b.length) {
            isOkay = false;
        }
        for (int i = 0; i != b.length; i++) {
            if (a[i] != b[i]) {
                isOkay = false;
            }
        }
        return isOkay;
    }

    private void clearBlock(byte[] block2) {
        for (int i = 0; i != block2.length; i++) {
            block2[i] = 0;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.SignerWithRecovery
    public void updateWithRecoveredMessage(byte[] signature) throws InvalidCipherTextException {
        int tLength;
        byte[] block2 = this.cipher.processBlock(signature, 0, signature.length);
        if (block2.length < (this.keyBits + 7) / 8) {
            byte[] tmp = new byte[((this.keyBits + 7) / 8)];
            System.arraycopy(block2, 0, tmp, tmp.length - block2.length, block2.length);
            clearBlock(block2);
            block2 = tmp;
        }
        if (((block2[block2.length - 1] & 255) ^ 188) == 0) {
            tLength = 1;
        } else {
            int sigTrail = ((block2[block2.length - 2] & 255) << 8) | (block2[block2.length - 1] & 255);
            Integer trailerObj = ISOTrailers.getTrailer(this.digest);
            if (trailerObj != null) {
                int trailer2 = trailerObj.intValue();
                if (sigTrail == trailer2 || (trailer2 == 15052 && sigTrail == 16588)) {
                    tLength = 2;
                } else {
                    throw new IllegalStateException("signer initialised with wrong digest for trailer " + sigTrail);
                }
            } else {
                throw new IllegalArgumentException("unrecognised hash in signature");
            }
        }
        this.digest.doFinal(new byte[this.hLen], 0);
        byte[] dbMask = maskGeneratorFunction1(block2, (block2.length - this.hLen) - tLength, this.hLen, (block2.length - this.hLen) - tLength);
        for (int i = 0; i != dbMask.length; i++) {
            block2[i] = (byte) (block2[i] ^ dbMask[i]);
        }
        block2[0] = (byte) (block2[0] & Byte.MAX_VALUE);
        int mStart = 0;
        while (mStart != block2.length && block2[mStart] != 1) {
            mStart++;
        }
        int mStart2 = mStart + 1;
        if (mStart2 >= block2.length) {
            clearBlock(block2);
        }
        this.fullMessage = mStart2 > 1;
        this.recoveredMessage = new byte[((dbMask.length - mStart2) - this.saltLength)];
        System.arraycopy(block2, mStart2, this.recoveredMessage, 0, this.recoveredMessage.length);
        System.arraycopy(this.recoveredMessage, 0, this.mBuf, 0, this.recoveredMessage.length);
        this.preSig = signature;
        this.preBlock = block2;
        this.preMStart = mStart2;
        this.preTLength = tLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte b) {
        if (this.preSig != null || this.messageLength >= this.mBuf.length) {
            this.digest.update(b);
            return;
        }
        byte[] bArr = this.mBuf;
        int i = this.messageLength;
        this.messageLength = i + 1;
        bArr[i] = b;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte[] in, int off, int len) {
        if (this.preSig == null) {
            while (len > 0 && this.messageLength < this.mBuf.length) {
                update(in[off]);
                off++;
                len--;
            }
        }
        if (len > 0) {
            this.digest.update(in, off, len);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void reset() {
        this.digest.reset();
        this.messageLength = 0;
        if (this.mBuf != null) {
            clearBlock(this.mBuf);
        }
        if (this.recoveredMessage != null) {
            clearBlock(this.recoveredMessage);
            this.recoveredMessage = null;
        }
        this.fullMessage = false;
        if (this.preSig != null) {
            this.preSig = null;
            clearBlock(this.preBlock);
            this.preBlock = null;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public byte[] generateSignature() throws CryptoException {
        byte[] salt;
        byte[] m2Hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(m2Hash, 0);
        byte[] C = new byte[8];
        LtoOSP((long) (this.messageLength * 8), C);
        this.digest.update(C, 0, C.length);
        this.digest.update(this.mBuf, 0, this.messageLength);
        this.digest.update(m2Hash, 0, m2Hash.length);
        if (this.standardSalt != null) {
            salt = this.standardSalt;
        } else {
            salt = new byte[this.saltLength];
            this.random.nextBytes(salt);
        }
        this.digest.update(salt, 0, salt.length);
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        int tLength = 2;
        if (this.trailer == 188) {
            tLength = 1;
        }
        int off = ((((this.block.length - this.messageLength) - salt.length) - this.hLen) - tLength) - 1;
        this.block[off] = 1;
        System.arraycopy(this.mBuf, 0, this.block, off + 1, this.messageLength);
        System.arraycopy(salt, 0, this.block, off + 1 + this.messageLength, salt.length);
        byte[] dbMask = maskGeneratorFunction1(hash, 0, hash.length, (this.block.length - this.hLen) - tLength);
        for (int i = 0; i != dbMask.length; i++) {
            byte[] bArr = this.block;
            bArr[i] = (byte) (bArr[i] ^ dbMask[i]);
        }
        System.arraycopy(hash, 0, this.block, (this.block.length - this.hLen) - tLength, this.hLen);
        if (this.trailer == 188) {
            this.block[this.block.length - 1] = PSSSigner.TRAILER_IMPLICIT;
        } else {
            this.block[this.block.length - 2] = (byte) (this.trailer >>> 8);
            this.block[this.block.length - 1] = (byte) this.trailer;
        }
        byte[] bArr2 = this.block;
        bArr2[0] = (byte) (bArr2[0] & Byte.MAX_VALUE);
        byte[] b = this.cipher.processBlock(this.block, 0, this.block.length);
        this.recoveredMessage = new byte[this.messageLength];
        this.fullMessage = this.messageLength <= this.mBuf.length;
        System.arraycopy(this.mBuf, 0, this.recoveredMessage, 0, this.recoveredMessage.length);
        clearBlock(this.mBuf);
        clearBlock(this.block);
        this.messageLength = 0;
        return b;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public boolean verifySignature(byte[] signature) {
        byte[] m2Hash = new byte[this.hLen];
        this.digest.doFinal(m2Hash, 0);
        if (this.preSig == null) {
            try {
                updateWithRecoveredMessage(signature);
            } catch (Exception e) {
                return false;
            }
        } else if (!Arrays.areEqual(this.preSig, signature)) {
            throw new IllegalStateException("updateWithRecoveredMessage called on different signature");
        }
        byte[] block2 = this.preBlock;
        int mStart = this.preMStart;
        int tLength = this.preTLength;
        this.preSig = null;
        this.preBlock = null;
        byte[] C = new byte[8];
        LtoOSP((long) (this.recoveredMessage.length * 8), C);
        this.digest.update(C, 0, C.length);
        if (this.recoveredMessage.length != 0) {
            this.digest.update(this.recoveredMessage, 0, this.recoveredMessage.length);
        }
        this.digest.update(m2Hash, 0, m2Hash.length);
        if (this.standardSalt != null) {
            this.digest.update(this.standardSalt, 0, this.standardSalt.length);
        } else {
            this.digest.update(block2, this.recoveredMessage.length + mStart, this.saltLength);
        }
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        int off = (block2.length - tLength) - hash.length;
        boolean isOkay = true;
        for (int i = 0; i != hash.length; i++) {
            if (hash[i] != block2[off + i]) {
                isOkay = false;
            }
        }
        clearBlock(block2);
        clearBlock(hash);
        if (!isOkay) {
            this.fullMessage = false;
            this.messageLength = 0;
            clearBlock(this.recoveredMessage);
            return false;
        } else if (this.messageLength == 0 || isSameAs(this.mBuf, this.recoveredMessage)) {
            this.messageLength = 0;
            clearBlock(this.mBuf);
            return true;
        } else {
            this.messageLength = 0;
            clearBlock(this.mBuf);
            return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.SignerWithRecovery
    public boolean hasFullMessage() {
        return this.fullMessage;
    }

    @Override // com.mi.car.jsse.easysec.crypto.SignerWithRecovery
    public byte[] getRecoveredMessage() {
        return this.recoveredMessage;
    }

    private void ItoOSP(int i, byte[] sp) {
        sp[0] = (byte) (i >>> 24);
        sp[1] = (byte) (i >>> 16);
        sp[2] = (byte) (i >>> 8);
        sp[3] = (byte) (i >>> 0);
    }

    private void LtoOSP(long l, byte[] sp) {
        sp[0] = (byte) ((int) (l >>> 56));
        sp[1] = (byte) ((int) (l >>> 48));
        sp[2] = (byte) ((int) (l >>> 40));
        sp[3] = (byte) ((int) (l >>> 32));
        sp[4] = (byte) ((int) (l >>> 24));
        sp[5] = (byte) ((int) (l >>> 16));
        sp[6] = (byte) ((int) (l >>> 8));
        sp[7] = (byte) ((int) (l >>> 0));
    }

    private byte[] maskGeneratorFunction1(byte[] Z, int zOff, int zLen, int length) {
        byte[] mask = new byte[length];
        byte[] hashBuf = new byte[this.hLen];
        byte[] C = new byte[4];
        int counter = 0;
        this.digest.reset();
        while (counter < length / this.hLen) {
            ItoOSP(counter, C);
            this.digest.update(Z, zOff, zLen);
            this.digest.update(C, 0, C.length);
            this.digest.doFinal(hashBuf, 0);
            System.arraycopy(hashBuf, 0, mask, this.hLen * counter, this.hLen);
            counter++;
        }
        if (this.hLen * counter < length) {
            ItoOSP(counter, C);
            this.digest.update(Z, zOff, zLen);
            this.digest.update(C, 0, C.length);
            this.digest.doFinal(hashBuf, 0);
            System.arraycopy(hashBuf, 0, mask, this.hLen * counter, mask.length - (this.hLen * counter));
        }
        return mask;
    }
}
