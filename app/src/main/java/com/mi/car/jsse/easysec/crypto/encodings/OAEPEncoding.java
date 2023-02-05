package com.mi.car.jsse.easysec.crypto.encodings;

import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.util.DigestFactory;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;
import java.security.SecureRandom;

public class OAEPEncoding implements AsymmetricBlockCipher {
    private byte[] defHash;
    private AsymmetricBlockCipher engine;
    private boolean forEncryption;
    private Digest mgf1Hash;
    private SecureRandom random;

    public OAEPEncoding(AsymmetricBlockCipher cipher) {
        this(cipher, DigestFactory.createSHA1(), null);
    }

    public OAEPEncoding(AsymmetricBlockCipher cipher, Digest hash) {
        this(cipher, hash, null);
    }

    public OAEPEncoding(AsymmetricBlockCipher cipher, Digest hash, byte[] encodingParams) {
        this(cipher, hash, hash, encodingParams);
    }

    public OAEPEncoding(AsymmetricBlockCipher cipher, Digest hash, Digest mgf1Hash2, byte[] encodingParams) {
        this.engine = cipher;
        this.mgf1Hash = mgf1Hash2;
        this.defHash = new byte[hash.getDigestSize()];
        hash.reset();
        if (encodingParams != null) {
            hash.update(encodingParams, 0, encodingParams.length);
        }
        hash.doFinal(this.defHash, 0);
    }

    public AsymmetricBlockCipher getUnderlyingCipher() {
        return this.engine;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public void init(boolean forEncryption2, CipherParameters param) {
        if (param instanceof ParametersWithRandom) {
            this.random = ((ParametersWithRandom) param).getRandom();
        } else {
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }
        this.engine.init(forEncryption2, param);
        this.forEncryption = forEncryption2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        int baseBlockSize = this.engine.getInputBlockSize();
        if (this.forEncryption) {
            return (baseBlockSize - 1) - (this.defHash.length * 2);
        }
        return baseBlockSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        int baseBlockSize = this.engine.getOutputBlockSize();
        return this.forEncryption ? baseBlockSize : (baseBlockSize - 1) - (this.defHash.length * 2);
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        if (this.forEncryption) {
            return encodeBlock(in, inOff, inLen);
        }
        return decodeBlock(in, inOff, inLen);
    }

    public byte[] encodeBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        if (inLen > getInputBlockSize()) {
            throw new DataLengthException("input data too long");
        }
        byte[] block = new byte[(getInputBlockSize() + 1 + (this.defHash.length * 2))];
        System.arraycopy(in, inOff, block, block.length - inLen, inLen);
        block[(block.length - inLen) - 1] = 1;
        System.arraycopy(this.defHash, 0, block, this.defHash.length, this.defHash.length);
        byte[] seed = new byte[this.defHash.length];
        this.random.nextBytes(seed);
        byte[] mask = maskGeneratorFunction1(seed, 0, seed.length, block.length - this.defHash.length);
        for (int i = this.defHash.length; i != block.length; i++) {
            block[i] = (byte) (block[i] ^ mask[i - this.defHash.length]);
        }
        System.arraycopy(seed, 0, block, 0, this.defHash.length);
        byte[] mask2 = maskGeneratorFunction1(block, this.defHash.length, block.length - this.defHash.length, this.defHash.length);
        for (int i2 = 0; i2 != this.defHash.length; i2++) {
            block[i2] = (byte) (block[i2] ^ mask2[i2]);
        }
        return this.engine.processBlock(block, 0, block.length);
    }

    public byte[] decodeBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        byte[] data = this.engine.processBlock(in, inOff, inLen);
        byte[] block = new byte[this.engine.getOutputBlockSize()];
        int wrongMask = (block.length - ((this.defHash.length * 2) + 1)) >> 31;
        if (data.length <= block.length) {
            System.arraycopy(data, 0, block, block.length - data.length, data.length);
        } else {
            System.arraycopy(data, 0, block, 0, block.length);
            wrongMask |= 1;
        }
        byte[] mask = maskGeneratorFunction1(block, this.defHash.length, block.length - this.defHash.length, this.defHash.length);
        for (int i = 0; i != this.defHash.length; i++) {
            block[i] = (byte) (block[i] ^ mask[i]);
        }
        byte[] mask2 = maskGeneratorFunction1(block, 0, this.defHash.length, block.length - this.defHash.length);
        for (int i2 = this.defHash.length; i2 != block.length; i2++) {
            block[i2] = (byte) (block[i2] ^ mask2[i2 - this.defHash.length]);
        }
        for (int i3 = 0; i3 != this.defHash.length; i3++) {
            wrongMask |= this.defHash[i3] ^ block[this.defHash.length + i3];
        }
        int start = -1;
        for (int index = this.defHash.length * 2; index != block.length; index++) {
            start += index & (((-(block[index] & 255)) & start) >> 31);
        }
        int start2 = start + 1;
        if ((wrongMask | (start >> 31) | (block[start2] ^ 1)) != 0) {
            Arrays.fill(block, (byte) 0);
            throw new InvalidCipherTextException("data wrong");
        }
        int start3 = start2 + 1;
        byte[] output = new byte[(block.length - start3)];
        System.arraycopy(block, start3, output, 0, output.length);
        Arrays.fill(block, (byte) 0);
        return output;
    }

    private byte[] maskGeneratorFunction1(byte[] Z, int zOff, int zLen, int length) {
        byte[] mask = new byte[length];
        byte[] hashBuf = new byte[this.mgf1Hash.getDigestSize()];
        byte[] C = new byte[4];
        int counter = 0;
        this.mgf1Hash.reset();
        while (counter < length / hashBuf.length) {
            Pack.intToBigEndian(counter, C, 0);
            this.mgf1Hash.update(Z, zOff, zLen);
            this.mgf1Hash.update(C, 0, C.length);
            this.mgf1Hash.doFinal(hashBuf, 0);
            System.arraycopy(hashBuf, 0, mask, hashBuf.length * counter, hashBuf.length);
            counter++;
        }
        if (hashBuf.length * counter < length) {
            Pack.intToBigEndian(counter, C, 0);
            this.mgf1Hash.update(Z, zOff, zLen);
            this.mgf1Hash.update(C, 0, C.length);
            this.mgf1Hash.doFinal(hashBuf, 0);
            System.arraycopy(hashBuf, 0, mask, hashBuf.length * counter, mask.length - (hashBuf.length * counter));
        }
        return mask;
    }
}
