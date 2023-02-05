package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.modes.GCFBBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithSBox;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithUKM;
import com.mi.car.jsse.easysec.util.Pack;

public class CryptoProWrapEngine extends GOST28147WrapEngine {
    @Override // com.mi.car.jsse.easysec.crypto.Wrapper, com.mi.car.jsse.easysec.crypto.engines.GOST28147WrapEngine
    public void init(boolean forWrapping, CipherParameters param) {
        KeyParameter kParam;
        if (param instanceof ParametersWithRandom) {
            param = ((ParametersWithRandom) param).getParameters();
        }
        ParametersWithUKM pU = (ParametersWithUKM) param;
        byte[] sBox = null;
        if (pU.getParameters() instanceof ParametersWithSBox) {
            kParam = (KeyParameter) ((ParametersWithSBox) pU.getParameters()).getParameters();
            sBox = ((ParametersWithSBox) pU.getParameters()).getSBox();
        } else {
            kParam = (KeyParameter) pU.getParameters();
        }
        KeyParameter kParam2 = new KeyParameter(cryptoProDiversify(kParam.getKey(), pU.getUKM(), sBox));
        if (sBox != null) {
            super.init(forWrapping, new ParametersWithUKM(new ParametersWithSBox(kParam2, sBox), pU.getUKM()));
        } else {
            super.init(forWrapping, new ParametersWithUKM(kParam2, pU.getUKM()));
        }
    }

    private static byte[] cryptoProDiversify(byte[] K, byte[] ukm, byte[] sBox) {
        for (int i = 0; i != 8; i++) {
            int sOn = 0;
            int sOff = 0;
            for (int j = 0; j != 8; j++) {
                int kj = Pack.littleEndianToInt(K, j * 4);
                if (bitSet(ukm[i], j)) {
                    sOn += kj;
                } else {
                    sOff += kj;
                }
            }
            byte[] s = new byte[8];
            Pack.intToLittleEndian(sOn, s, 0);
            Pack.intToLittleEndian(sOff, s, 4);
            GCFBBlockCipher c = new GCFBBlockCipher(new GOST28147Engine());
            c.init(true, new ParametersWithIV(new ParametersWithSBox(new KeyParameter(K), sBox), s));
            c.processBlock(K, 0, K, 0);
            c.processBlock(K, 8, K, 8);
            c.processBlock(K, 16, K, 16);
            c.processBlock(K, 24, K, 24);
        }
        return K;
    }

    private static boolean bitSet(byte v, int bitNo) {
        return ((1 << bitNo) & v) != 0;
    }
}
