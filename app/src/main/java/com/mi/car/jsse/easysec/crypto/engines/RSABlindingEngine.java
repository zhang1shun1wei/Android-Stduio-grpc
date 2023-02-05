package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.RSABlindingParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;

public class RSABlindingEngine implements AsymmetricBlockCipher {
    private BigInteger blindingFactor;
    private RSACoreEngine core = new RSACoreEngine();
    private boolean forEncryption;
    private RSAKeyParameters key;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public void init(boolean forEncryption2, CipherParameters param) {
        RSABlindingParameters p;
        if (param instanceof ParametersWithRandom) {
            p = (RSABlindingParameters) ((ParametersWithRandom) param).getParameters();
        } else {
            p = (RSABlindingParameters) param;
        }
        this.core.init(forEncryption2, p.getPublicKey());
        this.forEncryption = forEncryption2;
        this.key = p.getPublicKey();
        this.blindingFactor = p.getBlindingFactor();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        return this.core.getInputBlockSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        return this.core.getOutputBlockSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] in, int inOff, int inLen) {
        BigInteger msg;
        BigInteger msg2 = this.core.convertInput(in, inOff, inLen);
        if (this.forEncryption) {
            msg = blindMessage(msg2);
        } else {
            msg = unblindMessage(msg2);
        }
        return this.core.convertOutput(msg);
    }

    private BigInteger blindMessage(BigInteger msg) {
        return msg.multiply(this.blindingFactor.modPow(this.key.getExponent(), this.key.getModulus())).mod(this.key.getModulus());
    }

    private BigInteger unblindMessage(BigInteger blindedMsg) {
        BigInteger m = this.key.getModulus();
        return blindedMsg.multiply(BigIntegers.modOddInverse(m, this.blindingFactor)).mod(m);
    }
}
