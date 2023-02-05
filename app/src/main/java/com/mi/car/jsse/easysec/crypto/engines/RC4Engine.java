package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.StreamCipher;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;

public class RC4Engine implements StreamCipher {
    private static final int STATE_LENGTH = 256;
    private byte[] engineState = null;
    private byte[] workingKey = null;
    private int x = 0;
    private int y = 0;

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean forEncryption, CipherParameters params) {
        if (params instanceof KeyParameter) {
            this.workingKey = ((KeyParameter) params).getKey();
            setKey(this.workingKey);
            return;
        }
        throw new IllegalArgumentException("invalid parameter passed to RC4 init - " + params.getClass().getName());
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return "RC4";
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public byte returnByte(byte in) {
        this.x = (this.x + 1) & GF2Field.MASK;
        this.y = (this.engineState[this.x] + this.y) & GF2Field.MASK;
        byte tmp = this.engineState[this.x];
        this.engineState[this.x] = this.engineState[this.y];
        this.engineState[this.y] = tmp;
        return (byte) (this.engineState[(this.engineState[this.x] + this.engineState[this.y]) & GF2Field.MASK] ^ in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) {
        if (inOff + len > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff + len > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            for (int i = 0; i < len; i++) {
                this.x = (this.x + 1) & GF2Field.MASK;
                this.y = (this.engineState[this.x] + this.y) & GF2Field.MASK;
                byte tmp = this.engineState[this.x];
                this.engineState[this.x] = this.engineState[this.y];
                this.engineState[this.y] = tmp;
                out[i + outOff] = (byte) (in[i + inOff] ^ this.engineState[(this.engineState[this.x] + this.engineState[this.y]) & GF2Field.MASK]);
            }
            return len;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        setKey(this.workingKey);
    }

    private void setKey(byte[] keyBytes) {
        this.workingKey = keyBytes;
        this.x = 0;
        this.y = 0;
        if (this.engineState == null) {
            this.engineState = new byte[256];
        }
        for (int i = 0; i < 256; i++) {
            this.engineState[i] = (byte) i;
        }
        int i1 = 0;
        int i2 = 0;
        for (int i3 = 0; i3 < 256; i3++) {
            i2 = ((keyBytes[i1] & 255) + this.engineState[i3] + i2) & GF2Field.MASK;
            byte tmp = this.engineState[i3];
            this.engineState[i3] = this.engineState[i2];
            this.engineState[i2] = tmp;
            i1 = (i1 + 1) % keyBytes.length;
        }
    }
}
