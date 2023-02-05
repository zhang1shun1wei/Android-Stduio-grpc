package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.PBEParametersGenerator;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.util.DigestFactory;

public class PKCS5S2ParametersGenerator extends PBEParametersGenerator {
    private Mac hMac;
    private byte[] state;

    public PKCS5S2ParametersGenerator() {
        this(DigestFactory.createSHA1());
    }

    public PKCS5S2ParametersGenerator(Digest digest) {
        this.hMac = new HMac(digest);
        this.state = new byte[this.hMac.getMacSize()];
    }

    private void F(byte[] S, int c, byte[] iBuf, byte[] out, int outOff) {
        if (c == 0) {
            throw new IllegalArgumentException("iteration count must be at least 1.");
        }
        if (S != null) {
            this.hMac.update(S, 0, S.length);
        }
        this.hMac.update(iBuf, 0, iBuf.length);
        this.hMac.doFinal(this.state, 0);
        System.arraycopy(this.state, 0, out, outOff, this.state.length);
        for (int count = 1; count < c; count++) {
            this.hMac.update(this.state, 0, this.state.length);
            this.hMac.doFinal(this.state, 0);
            for (int j = 0; j != this.state.length; j++) {
                int i = outOff + j;
                out[i] = (byte) (out[i] ^ this.state[j]);
            }
        }
    }

    private byte[] generateDerivedKey(int dkLen) {
        int hLen = this.hMac.getMacSize();
        int l = ((dkLen + hLen) - 1) / hLen;
        byte[] iBuf = new byte[4];
        byte[] outBytes = new byte[(l * hLen)];
        int outPos = 0;
        this.hMac.init(new KeyParameter(this.password));
        for (int i = 1; i <= l; i++) {
            int pos = 3;
            while (true) {
                byte b = (byte) (iBuf[pos] + 1);
                iBuf[pos] = b;
                if (b != 0) {
                    break;
                }
                pos--;
            }
            F(this.salt, this.iterationCount, iBuf, outBytes, outPos);
            outPos += hLen;
        }
        return outBytes;
    }

    @Override // com.mi.car.jsse.easysec.crypto.PBEParametersGenerator
    public CipherParameters generateDerivedParameters(int keySize) {
        int keySize2 = keySize / 8;
        return new KeyParameter(generateDerivedKey(keySize2), 0, keySize2);
    }

    @Override // com.mi.car.jsse.easysec.crypto.PBEParametersGenerator
    public CipherParameters generateDerivedParameters(int keySize, int ivSize) {
        int keySize2 = keySize / 8;
        int ivSize2 = ivSize / 8;
        byte[] dKey = generateDerivedKey(keySize2 + ivSize2);
        return new ParametersWithIV(new KeyParameter(dKey, 0, keySize2), dKey, keySize2, ivSize2);
    }

    @Override // com.mi.car.jsse.easysec.crypto.PBEParametersGenerator
    public CipherParameters generateDerivedMacParameters(int keySize) {
        return generateDerivedParameters(keySize);
    }
}
