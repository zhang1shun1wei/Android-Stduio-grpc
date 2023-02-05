package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class JceChaCha20Poly1305 implements TlsAEADCipherImpl {
    private static final byte[] ZEROES = new byte[15];
    protected byte[] additionalData;
    protected final Cipher cipher;
    protected SecretKey cipherKey;
    protected final int cipherMode;
    protected final Mac mac;

    public JceChaCha20Poly1305(JcaJceHelper helper, boolean isEncrypting) throws GeneralSecurityException {
        this.cipher = helper.createCipher("ChaCha7539");
        this.mac = helper.createMac("Poly1305");
        this.cipherMode = isEncrypting ? 1 : 2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException {
        try {
            if (this.cipherMode == 1) {
                byte[] tmp = new byte[(inputLength + 64)];
                System.arraycopy(input, inputOffset, tmp, 64, inputLength);
                runCipher(tmp);
                System.arraycopy(tmp, 64, output, outputOffset, inputLength);
                initMAC(tmp);
                updateMAC(this.additionalData, 0, this.additionalData.length);
                updateMAC(tmp, 64, inputLength);
                byte[] lengths = new byte[16];
                Pack.longToLittleEndian(((long) this.additionalData.length) & 4294967295L, lengths, 0);
                Pack.longToLittleEndian(((long) inputLength) & 4294967295L, lengths, 8);
                this.mac.update(lengths, 0, 16);
                this.mac.doFinal(output, outputOffset + inputLength);
                return inputLength + 16;
            }
            int ciphertextLength = inputLength - 16;
            byte[] tmp2 = new byte[(ciphertextLength + 64)];
            System.arraycopy(input, inputOffset, tmp2, 64, ciphertextLength);
            runCipher(tmp2);
            initMAC(tmp2);
            updateMAC(this.additionalData, 0, this.additionalData.length);
            updateMAC(input, inputOffset, ciphertextLength);
            byte[] expectedMac = new byte[16];
            Pack.longToLittleEndian(((long) this.additionalData.length) & 4294967295L, expectedMac, 0);
            Pack.longToLittleEndian(((long) ciphertextLength) & 4294967295L, expectedMac, 8);
            this.mac.update(expectedMac, 0, 16);
            this.mac.doFinal(expectedMac, 0);
            if (!TlsUtils.constantTimeAreEqual(16, expectedMac, 0, input, inputOffset + ciphertextLength)) {
                throw new TlsFatalAlert((short) 20);
            }
            System.arraycopy(tmp2, 64, output, outputOffset, ciphertextLength);
            return ciphertextLength;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public int getOutputSize(int inputLength) {
        return this.cipherMode == 1 ? inputLength + 16 : inputLength - 16;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public void init(byte[] nonce, int macSize, byte[] additionalData2) throws IOException {
        if (nonce != null && nonce.length == 12 && macSize == 16) {
            try {
                this.cipher.init(this.cipherMode, this.cipherKey, new IvParameterSpec(nonce), (SecureRandom) null);
                this.additionalData = additionalData2;
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        } else {
            throw new TlsFatalAlert((short) 80);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public void setKey(byte[] key, int keyOff, int keyLen) throws IOException {
        this.cipherKey = new SecretKeySpec(key, keyOff, keyLen, "ChaCha7539");
    }

    /* access modifiers changed from: protected */
    public void initMAC(byte[] firstBlock) throws InvalidKeyException {
        this.mac.init(new SecretKeySpec(firstBlock, 0, 32, "Poly1305"));
        for (int i = 0; i < 64; i++) {
            firstBlock[i] = 0;
        }
    }

    /* access modifiers changed from: protected */
    public void runCipher(byte[] buf) throws GeneralSecurityException {
        if (buf.length != this.cipher.doFinal(buf, 0, buf.length, buf, 0)) {
            throw new IllegalStateException();
        }
    }

    /* access modifiers changed from: protected */
    public void updateMAC(byte[] buf, int off, int len) {
        this.mac.update(buf, off, len);
        int partial = len % 16;
        if (partial != 0) {
            this.mac.update(ZEROES, 0, 16 - partial);
        }
    }
}
