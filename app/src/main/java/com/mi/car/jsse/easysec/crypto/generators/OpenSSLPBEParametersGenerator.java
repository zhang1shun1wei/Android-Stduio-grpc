package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.PBEParametersGenerator;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.util.DigestFactory;

public class OpenSSLPBEParametersGenerator extends PBEParametersGenerator {
    private final Digest digest;

    public OpenSSLPBEParametersGenerator() {
        this(DigestFactory.createMD5());
    }

    public OpenSSLPBEParametersGenerator(Digest digest2) {
        this.digest = digest2;
    }

    public void init(byte[] password, byte[] salt) {
        super.init(password, salt, 1);
    }

    private byte[] generateDerivedKey(int bytesNeeded) {
        int len;
        byte[] buf = new byte[this.digest.getDigestSize()];
        byte[] key = new byte[bytesNeeded];
        int offset = 0;
        while (true) {
            this.digest.update(this.password, 0, this.password.length);
            this.digest.update(this.salt, 0, this.salt.length);
            this.digest.doFinal(buf, 0);
            if (bytesNeeded > buf.length) {
                len = buf.length;
            } else {
                len = bytesNeeded;
            }
            System.arraycopy(buf, 0, key, offset, len);
            offset += len;
            bytesNeeded -= len;
            if (bytesNeeded == 0) {
                return key;
            }
            this.digest.reset();
            this.digest.update(buf, 0, buf.length);
        }
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
