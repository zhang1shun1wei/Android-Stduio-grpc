package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.Wrapper;
import com.mi.car.jsse.easysec.crypto.modes.CBCBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public class RFC3211WrapEngine implements Wrapper {
    private CBCBlockCipher engine;
    private boolean forWrapping;
    private ParametersWithIV param;
    private SecureRandom rand;

    public RFC3211WrapEngine(BlockCipher engine2) {
        this.engine = new CBCBlockCipher(engine2);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public void init(boolean forWrapping2, CipherParameters param2) {
        this.forWrapping = forWrapping2;
        if (param2 instanceof ParametersWithRandom) {
            ParametersWithRandom p = (ParametersWithRandom) param2;
            this.rand = p.getRandom();
            if (!(p.getParameters() instanceof ParametersWithIV)) {
                throw new IllegalArgumentException("RFC3211Wrap requires an IV");
            }
            this.param = (ParametersWithIV) p.getParameters();
            return;
        }
        if (forWrapping2) {
            this.rand = CryptoServicesRegistrar.getSecureRandom();
        }
        if (!(param2 instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("RFC3211Wrap requires an IV");
        }
        this.param = (ParametersWithIV) param2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public String getAlgorithmName() {
        return this.engine.getUnderlyingCipher().getAlgorithmName() + "/RFC3211Wrap";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public byte[] wrap(byte[] in, int inOff, int inLen) {
        int i;
        byte[] cekBlock;
        if (!this.forWrapping) {
            throw new IllegalStateException("not set for wrapping");
        } else if (inLen > 255 || inLen < 0) {
            throw new IllegalArgumentException("input must be from 0 to 255 bytes");
        } else {
            this.engine.init(true, this.param);
            int blockSize = this.engine.getBlockSize();
            if (inLen + 4 < blockSize * 2) {
                cekBlock = new byte[(blockSize * 2)];
            } else {
                if ((inLen + 4) % blockSize == 0) {
                    i = inLen + 4;
                } else {
                    i = (((inLen + 4) / blockSize) + 1) * blockSize;
                }
                cekBlock = new byte[i];
            }
            cekBlock[0] = (byte) inLen;
            System.arraycopy(in, inOff, cekBlock, 4, inLen);
            byte[] pad = new byte[(cekBlock.length - (inLen + 4))];
            this.rand.nextBytes(pad);
            System.arraycopy(pad, 0, cekBlock, inLen + 4, pad.length);
            cekBlock[1] = (byte) (cekBlock[4] ^ -1);
            cekBlock[2] = (byte) (cekBlock[5] ^ -1);
            cekBlock[3] = (byte) (cekBlock[6] ^ -1);
            for (int i2 = 0; i2 < cekBlock.length; i2 += blockSize) {
                this.engine.processBlock(cekBlock, i2, cekBlock, i2);
            }
            for (int i3 = 0; i3 < cekBlock.length; i3 += blockSize) {
                this.engine.processBlock(cekBlock, i3, cekBlock, i3);
            }
            return cekBlock;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public byte[] unwrap(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        byte[] key;
        if (this.forWrapping) {
            throw new IllegalStateException("not set for unwrapping");
        }
        int blockSize = this.engine.getBlockSize();
        if (inLen < blockSize * 2) {
            throw new InvalidCipherTextException("input too short");
        }
        byte[] cekBlock = new byte[inLen];
        byte[] iv = new byte[blockSize];
        System.arraycopy(in, inOff, cekBlock, 0, inLen);
        System.arraycopy(in, inOff, iv, 0, iv.length);
        this.engine.init(false, new ParametersWithIV(this.param.getParameters(), iv));
        for (int i = blockSize; i < cekBlock.length; i += blockSize) {
            this.engine.processBlock(cekBlock, i, cekBlock, i);
        }
        System.arraycopy(cekBlock, cekBlock.length - iv.length, iv, 0, iv.length);
        this.engine.init(false, new ParametersWithIV(this.param.getParameters(), iv));
        this.engine.processBlock(cekBlock, 0, cekBlock, 0);
        this.engine.init(false, this.param);
        for (int i2 = 0; i2 < cekBlock.length; i2 += blockSize) {
            this.engine.processBlock(cekBlock, i2, cekBlock, i2);
        }
        boolean invalidLength = (cekBlock[0] & 255) > cekBlock.length + -4;
        if (invalidLength) {
            key = new byte[(cekBlock.length - 4)];
        } else {
            key = new byte[(cekBlock[0] & 255)];
        }
        System.arraycopy(cekBlock, 4, key, 0, key.length);
        int nonEqual = 0;
        for (int i3 = 0; i3 != 3; i3++) {
            nonEqual |= cekBlock[i3 + 4] ^ ((byte) (cekBlock[i3 + 1] ^ -1));
        }
        Arrays.clear(cekBlock);
        if (!(nonEqual != 0) && !invalidLength) {
            return key;
        }
        throw new InvalidCipherTextException("wrapped key corrupted");
    }
}
