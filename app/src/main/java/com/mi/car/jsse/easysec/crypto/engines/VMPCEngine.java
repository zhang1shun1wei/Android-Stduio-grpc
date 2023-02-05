package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.StreamCipher;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;

public class VMPCEngine implements StreamCipher {
    protected byte[] P = null;
    protected byte n = 0;
    protected byte s = 0;
    protected byte[] workingIV;
    protected byte[] workingKey;

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return "VMPC";
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean forEncryption, CipherParameters params) {
        if (!(params instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("VMPC init parameters must include an IV");
        }
        ParametersWithIV ivParams = (ParametersWithIV) params;
        if (!(ivParams.getParameters() instanceof KeyParameter)) {
            throw new IllegalArgumentException("VMPC init parameters must include a key");
        }
        KeyParameter key = (KeyParameter) ivParams.getParameters();
        this.workingIV = ivParams.getIV();
        if (this.workingIV == null || this.workingIV.length < 1 || this.workingIV.length > 768) {
            throw new IllegalArgumentException("VMPC requires 1 to 768 bytes of IV");
        }
        this.workingKey = key.getKey();
        initKey(this.workingKey, this.workingIV);
    }

    /* access modifiers changed from: protected */
    public void initKey(byte[] keyBytes, byte[] ivBytes) {
        this.s = 0;
        this.P = new byte[256];
        for (int i = 0; i < 256; i++) {
            this.P[i] = (byte) i;
        }
        for (int m = 0; m < 768; m++) {
            this.s = this.P[(this.s + this.P[m & GF2Field.MASK] + keyBytes[m % keyBytes.length]) & GF2Field.MASK];
            byte temp = this.P[m & GF2Field.MASK];
            this.P[m & GF2Field.MASK] = this.P[this.s & 255];
            this.P[this.s & 255] = temp;
        }
        for (int m2 = 0; m2 < 768; m2++) {
            this.s = this.P[(this.s + this.P[m2 & GF2Field.MASK] + ivBytes[m2 % ivBytes.length]) & GF2Field.MASK];
            byte temp2 = this.P[m2 & GF2Field.MASK];
            this.P[m2 & GF2Field.MASK] = this.P[this.s & 255];
            this.P[this.s & 255] = temp2;
        }
        this.n = 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) {
        if (inOff + len > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff + len > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            for (int i = 0; i < len; i++) {
                this.s = this.P[(this.s + this.P[this.n & 255]) & GF2Field.MASK];
                byte z = this.P[(this.P[this.P[this.s & 255] & 255] + 1) & GF2Field.MASK];
                byte temp = this.P[this.n & 255];
                this.P[this.n & 255] = this.P[this.s & 255];
                this.P[this.s & 255] = temp;
                this.n = (byte) ((this.n + 1) & GF2Field.MASK);
                out[i + outOff] = (byte) (in[i + inOff] ^ z);
            }
            return len;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        initKey(this.workingKey, this.workingIV);
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public byte returnByte(byte in) {
        this.s = this.P[(this.s + this.P[this.n & 255]) & GF2Field.MASK];
        byte z = this.P[(this.P[this.P[this.s & 255] & 255] + 1) & GF2Field.MASK];
        byte temp = this.P[this.n & 255];
        this.P[this.n & 255] = this.P[this.s & 255];
        this.P[this.s & 255] = temp;
        this.n = (byte) ((this.n + 1) & GF2Field.MASK);
        return (byte) (in ^ z);
    }
}
