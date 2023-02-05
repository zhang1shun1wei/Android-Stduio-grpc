package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class JceBlockCipherWithCBCImplicitIVImpl implements TlsBlockCipherImpl {
    private static final int BUF_SIZE = 32768;
    private final String algorithm;
    private final Cipher cipher;
    private final boolean isEncrypting;
    private SecretKey key;
    private byte[] nextIV;

    public JceBlockCipherWithCBCImplicitIVImpl(Cipher cipher2, String algorithm2, boolean isEncrypting2) throws GeneralSecurityException {
        this.cipher = cipher2;
        this.algorithm = algorithm2;
        this.isEncrypting = isEncrypting2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public void setKey(byte[] key2, int keyOff, int keyLen) {
        this.key = new SecretKeySpec(key2, keyOff, keyLen, this.algorithm);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public void init(byte[] iv, int ivOff, int ivLen) {
        if (this.nextIV != null) {
            throw new IllegalStateException("unexpected reinitialization of an implicit-IV cipher");
        }
        this.nextIV = TlsUtils.copyOfRangeExact(iv, ivOff, ivOff + ivLen);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) {
        try {
            this.cipher.init(this.isEncrypting ? 1 : 2, this.key, new IvParameterSpec(this.nextIV), (SecureRandom) null);
            this.nextIV = null;
            if (!this.isEncrypting) {
                this.nextIV = TlsUtils.copyOfRangeExact(input, (inputOffset + inputLength) - this.cipher.getBlockSize(), inputOffset + inputLength);
            }
            int totLen = 0;
            while (inputLength > BUF_SIZE) {
                totLen += this.cipher.update(input, inputOffset, BUF_SIZE, output, outputOffset + totLen);
                inputOffset += BUF_SIZE;
                inputLength -= 32768;
            }
            int totLen2 = totLen + this.cipher.update(input, inputOffset, inputLength, output, outputOffset + totLen);
            int totLen3 = totLen2 + this.cipher.doFinal(output, outputOffset + totLen2);
            if (this.isEncrypting) {
                this.nextIV = TlsUtils.copyOfRangeExact(output, (outputOffset + totLen3) - this.cipher.getBlockSize(), outputOffset + totLen3);
            }
            return totLen3;
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }
}
