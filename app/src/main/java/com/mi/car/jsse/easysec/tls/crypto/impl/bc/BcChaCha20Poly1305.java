package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.engines.ChaCha7539Engine;
import com.mi.car.jsse.easysec.crypto.macs.Poly1305;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;

public class BcChaCha20Poly1305 implements TlsAEADCipherImpl {
    private static final byte[] ZEROES = new byte[15];
    protected int additionalDataLength;
    protected final ChaCha7539Engine cipher = new ChaCha7539Engine();
    protected final boolean isEncrypting;
    protected final Poly1305 mac = new Poly1305();

    public BcChaCha20Poly1305(boolean isEncrypting2) {
        this.isEncrypting = isEncrypting2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException {
        if (!this.isEncrypting) {
            int ciphertextLength = inputLength - 16;
            updateMAC(input, inputOffset, ciphertextLength);
            byte[] expectedMac = new byte[16];
            Pack.longToLittleEndian(((long) this.additionalDataLength) & 4294967295L, expectedMac, 0);
            Pack.longToLittleEndian(((long) ciphertextLength) & 4294967295L, expectedMac, 8);
            this.mac.update(expectedMac, 0, 16);
            this.mac.doFinal(expectedMac, 0);
            if (!TlsUtils.constantTimeAreEqual(16, expectedMac, 0, input, inputOffset + ciphertextLength)) {
                throw new TlsFatalAlert((short) 20);
            } else if (ciphertextLength == this.cipher.processBytes(input, inputOffset, ciphertextLength, output, outputOffset)) {
                return ciphertextLength;
            } else {
                throw new IllegalStateException();
            }
        } else if (inputLength != this.cipher.processBytes(input, inputOffset, inputLength, output, outputOffset)) {
            throw new IllegalStateException();
        } else {
            updateMAC(output, outputOffset, inputLength);
            byte[] lengths = new byte[16];
            Pack.longToLittleEndian(((long) this.additionalDataLength) & 4294967295L, lengths, 0);
            Pack.longToLittleEndian(((long) inputLength) & 4294967295L, lengths, 8);
            this.mac.update(lengths, 0, 16);
            this.mac.doFinal(output, outputOffset + inputLength);
            return inputLength + 16;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public int getOutputSize(int inputLength) {
        return this.isEncrypting ? inputLength + 16 : inputLength - 16;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public void init(byte[] nonce, int macSize, byte[] additionalData) throws IOException {
        if (nonce != null && nonce.length == 12 && macSize == 16) {
            this.cipher.init(this.isEncrypting, new ParametersWithIV((CipherParameters) null, nonce));
            initMAC();
            if (additionalData == null) {
                this.additionalDataLength = 0;
                return;
            }
            this.additionalDataLength = additionalData.length;
            updateMAC(additionalData, 0, additionalData.length);
            return;
        }
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public void setKey(byte[] key, int keyOff, int keyLen) throws IOException {
        this.cipher.init(this.isEncrypting, new ParametersWithIV(new KeyParameter(key, keyOff, keyLen), ZEROES, 0, 12));
    }

    /* access modifiers changed from: protected */
    public void initMAC() {
        byte[] firstBlock = new byte[64];
        this.cipher.processBytes(firstBlock, 0, 64, firstBlock, 0);
        this.mac.init(new KeyParameter(firstBlock, 0, 32));
        Arrays.fill(firstBlock, (byte) 0);
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
