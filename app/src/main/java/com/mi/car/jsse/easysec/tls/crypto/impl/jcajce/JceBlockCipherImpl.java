package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class JceBlockCipherImpl implements TlsBlockCipherImpl {
    private static final int BUF_SIZE = 32768;
    private final String algorithm;
    private final Cipher cipher;
    private final int cipherMode;
    private SecretKey key;
    private final int keySize;

    public JceBlockCipherImpl(Cipher cipher2, String algorithm2, int keySize2, boolean isEncrypting) throws GeneralSecurityException {
        this.cipher = cipher2;
        this.algorithm = algorithm2;
        this.keySize = keySize2;
        this.cipherMode = isEncrypting ? 1 : 2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public void setKey(byte[] key2, int keyOff, int keyLen) {
        if (this.keySize != keyLen) {
            throw new IllegalStateException();
        }
        this.key = new SecretKeySpec(key2, keyOff, keyLen, this.algorithm);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public void init(byte[] iv, int ivOff, int ivLen) {
        try {
            this.cipher.init(this.cipherMode, this.key, new IvParameterSpec(iv, ivOff, ivLen), (SecureRandom) null);
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws Exception {
        int totLen = 0;
        while (inputLength > BUF_SIZE) {
            try {
                totLen += this.cipher.update(input, inputOffset, BUF_SIZE, output, outputOffset + totLen);
                inputOffset += BUF_SIZE;
                inputLength -= 32768;
            } catch (GeneralSecurityException e) {
                throw Exceptions.illegalStateException(e.getMessage(), e);
            }
        }
        int totLen2 = totLen + this.cipher.update(input, inputOffset, inputLength, output, outputOffset + totLen);
        return totLen2 + this.cipher.doFinal(output, outputOffset + totLen2);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }
}
