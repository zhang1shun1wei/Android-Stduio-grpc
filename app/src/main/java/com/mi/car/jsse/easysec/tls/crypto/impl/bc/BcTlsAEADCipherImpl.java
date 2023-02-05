package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl;
import java.io.IOException;

/* access modifiers changed from: package-private */
public final class BcTlsAEADCipherImpl implements TlsAEADCipherImpl {
    private final AEADBlockCipher cipher;
    private final boolean isEncrypting;
    private KeyParameter key;

    BcTlsAEADCipherImpl(AEADBlockCipher cipher2, boolean isEncrypting2) {
        this.cipher = cipher2;
        this.isEncrypting = isEncrypting2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public void setKey(byte[] key2, int keyOff, int keyLen) {
        this.key = new KeyParameter(key2, keyOff, keyLen);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public void init(byte[] nonce, int macSize, byte[] additionalData) {
        this.cipher.init(this.isEncrypting, new AEADParameters(this.key, macSize * 8, nonce, additionalData));
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public int getOutputSize(int inputLength) {
        return this.cipher.getOutputSize(inputLength);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException {
        int len = this.cipher.processBytes(input, inputOffset, inputLength, output, outputOffset);
        try {
            return len + this.cipher.doFinal(output, outputOffset + len);
        } catch (InvalidCipherTextException e) {
            throw new TlsFatalAlert((short) 20, (Throwable) e);
        }
    }
}
