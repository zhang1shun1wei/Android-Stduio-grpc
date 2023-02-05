package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.StreamBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithSBox;

public class GCFBBlockCipher extends StreamBlockCipher {
    private static final byte[] C = {105, 0, 114, 34, 100, -55, 4, 35, -115, 58, -37, -106, 70, -23, 42, -60, 24, -2, -84, -108, 0, -19, 7, 18, -64, -122, -36, -62, -17, 76, -87, 43};
    private final CFBBlockCipher cfbEngine;
    private long counter = 0;
    private boolean forEncryption;
    private KeyParameter key;

    public GCFBBlockCipher(BlockCipher engine) {
        super(engine);
        this.cfbEngine = new CFBBlockCipher(engine, engine.getBlockSize() * 8);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean forEncryption2, CipherParameters params) throws IllegalArgumentException {
        this.counter = 0;
        this.cfbEngine.init(forEncryption2, params);
        this.forEncryption = forEncryption2;
        if (params instanceof ParametersWithIV) {
            params = ((ParametersWithIV) params).getParameters();
        }
        if (params instanceof ParametersWithRandom) {
            params = ((ParametersWithRandom) params).getParameters();
        }
        if (params instanceof ParametersWithSBox) {
            params = ((ParametersWithSBox) params).getParameters();
        }
        this.key = (KeyParameter) params;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        String name = this.cfbEngine.getAlgorithmName();
        return name.substring(0, name.indexOf(47)) + "/G" + name.substring(name.indexOf(47) + 1);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.cfbEngine.getBlockSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        processBytes(in, inOff, this.cfbEngine.getBlockSize(), out, outOff);
        return this.cfbEngine.getBlockSize();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.StreamBlockCipher
    public byte calculateByte(byte b) {
        if (this.counter > 0 && this.counter % 1024 == 0) {
            BlockCipher base = this.cfbEngine.getUnderlyingCipher();
            base.init(false, this.key);
            byte[] nextKey = new byte[32];
            base.processBlock(C, 0, nextKey, 0);
            base.processBlock(C, 8, nextKey, 8);
            base.processBlock(C, 16, nextKey, 16);
            base.processBlock(C, 24, nextKey, 24);
            this.key = new KeyParameter(nextKey);
            base.init(true, this.key);
            byte[] iv = this.cfbEngine.getCurrentIV();
            base.processBlock(iv, 0, iv, 0);
            this.cfbEngine.init(this.forEncryption, new ParametersWithIV(this.key, iv));
        }
        this.counter++;
        return this.cfbEngine.calculateByte(b);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        this.counter = 0;
        this.cfbEngine.reset();
    }
}
