package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl;

/* access modifiers changed from: package-private */
public final class BcTlsBlockCipherImpl implements TlsBlockCipherImpl {
    private final BlockCipher cipher;
    private final boolean isEncrypting;
    private KeyParameter key;

    BcTlsBlockCipherImpl(BlockCipher cipher2, boolean isEncrypting2) {
        this.cipher = cipher2;
        this.isEncrypting = isEncrypting2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public void setKey(byte[] key2, int keyOff, int keyLen) {
        this.key = new KeyParameter(key2, keyOff, keyLen);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public void init(byte[] iv, int ivOff, int ivLen) {
        this.cipher.init(this.isEncrypting, new ParametersWithIV(this.key, iv, ivOff, ivLen));
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) {
        int blockSize = this.cipher.getBlockSize();
        for (int i = 0; i < inputLength; i += blockSize) {
            this.cipher.processBlock(input, inputOffset + i, output, outputOffset + i);
        }
        return inputLength;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }
}
