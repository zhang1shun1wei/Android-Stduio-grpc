package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.Wrapper;
import com.mi.car.jsse.easysec.crypto.macs.GOST28147Mac;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithUKM;
import com.mi.car.jsse.easysec.util.Arrays;

public class GOST28147WrapEngine implements Wrapper {
    private GOST28147Engine cipher = new GOST28147Engine();
    private GOST28147Mac mac = new GOST28147Mac();

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public void init(boolean forWrapping, CipherParameters param) {
        if (param instanceof ParametersWithRandom) {
            param = ((ParametersWithRandom) param).getParameters();
        }
        ParametersWithUKM pU = (ParametersWithUKM) param;
        this.cipher.init(forWrapping, pU.getParameters());
        this.mac.init(new ParametersWithIV(pU.getParameters(), pU.getUKM()));
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public String getAlgorithmName() {
        return "GOST28147Wrap";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public byte[] wrap(byte[] input, int inOff, int inLen) {
        this.mac.update(input, inOff, inLen);
        byte[] wrappedKey = new byte[(this.mac.getMacSize() + inLen)];
        this.cipher.processBlock(input, inOff, wrappedKey, 0);
        this.cipher.processBlock(input, inOff + 8, wrappedKey, 8);
        this.cipher.processBlock(input, inOff + 16, wrappedKey, 16);
        this.cipher.processBlock(input, inOff + 24, wrappedKey, 24);
        this.mac.doFinal(wrappedKey, inLen);
        return wrappedKey;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public byte[] unwrap(byte[] input, int inOff, int inLen) throws InvalidCipherTextException {
        byte[] decKey = new byte[(inLen - this.mac.getMacSize())];
        this.cipher.processBlock(input, inOff, decKey, 0);
        this.cipher.processBlock(input, inOff + 8, decKey, 8);
        this.cipher.processBlock(input, inOff + 16, decKey, 16);
        this.cipher.processBlock(input, inOff + 24, decKey, 24);
        byte[] macResult = new byte[this.mac.getMacSize()];
        this.mac.update(decKey, 0, decKey.length);
        this.mac.doFinal(macResult, 0);
        byte[] macExpected = new byte[this.mac.getMacSize()];
        System.arraycopy(input, (inOff + inLen) - 4, macExpected, 0, this.mac.getMacSize());
        if (Arrays.constantTimeAreEqual(macResult, macExpected)) {
            return decKey;
        }
        throw new IllegalStateException("mac mismatch");
    }
}
