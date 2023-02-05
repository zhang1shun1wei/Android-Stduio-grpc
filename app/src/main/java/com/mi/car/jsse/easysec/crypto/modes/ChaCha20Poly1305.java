package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.engines.ChaCha7539Engine;
import com.mi.car.jsse.easysec.crypto.macs.Poly1305;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

public class ChaCha20Poly1305 implements AEADCipher {
    private static final long AAD_LIMIT = -1;
    private static final int BUF_SIZE = 64;
    private static final long DATA_LIMIT = 274877906880L;
    private static final int KEY_SIZE = 32;
    private static final int MAC_SIZE = 16;
    private static final int NONCE_SIZE = 12;
    private static final byte[] ZEROES = new byte[15];
    private long aadCount;
    private final byte[] buf;
    private int bufPos;
    private final ChaCha7539Engine chacha20;
    private long dataCount;
    private byte[] initialAAD;
    private final byte[] key;
    private final byte[] mac;
    private final byte[] nonce;
    private final Mac poly1305;
    private int state;

    private static final class State {
        static final int DEC_AAD = 6;
        static final int DEC_DATA = 7;
        static final int DEC_FINAL = 8;
        static final int DEC_INIT = 5;
        static final int ENC_AAD = 2;
        static final int ENC_DATA = 3;
        static final int ENC_FINAL = 4;
        static final int ENC_INIT = 1;
        static final int UNINITIALIZED = 0;

        private State() {
        }
    }

    public ChaCha20Poly1305() {
        this(new Poly1305());
    }

    public ChaCha20Poly1305(Mac poly13052) {
        this.key = new byte[32];
        this.nonce = new byte[12];
        this.buf = new byte[80];
        this.mac = new byte[16];
        this.state = 0;
        if (poly13052 == null) {
            throw new NullPointerException("'poly1305' cannot be null");
        } else if (16 != poly13052.getMacSize()) {
            throw new IllegalArgumentException("'poly1305' must be a 128-bit MAC");
        } else {
            this.chacha20 = new ChaCha7539Engine();
            this.poly1305 = poly13052;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return "ChaCha20Poly1305";
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        KeyParameter initKeyParam;
        byte[] initNonce;
        CipherParameters chacha20Params;
        if (params instanceof AEADParameters) {
            AEADParameters aeadParams = (AEADParameters) params;
            int macSizeBits = aeadParams.getMacSize();
            if (128 != macSizeBits) {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
            initKeyParam = aeadParams.getKey();
            initNonce = aeadParams.getNonce();
            chacha20Params = new ParametersWithIV(initKeyParam, initNonce);
            this.initialAAD = aeadParams.getAssociatedText();
        } else if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParams = (ParametersWithIV) params;
            initKeyParam = (KeyParameter) ivParams.getParameters();
            initNonce = ivParams.getIV();
            chacha20Params = ivParams;
            this.initialAAD = null;
        } else {
            throw new IllegalArgumentException("invalid parameters passed to ChaCha20Poly1305");
        }
        if (initKeyParam == null) {
            if (this.state == 0) {
                throw new IllegalArgumentException("Key must be specified in initial init");
            }
        } else if (32 != initKeyParam.getKey().length) {
            throw new IllegalArgumentException("Key must be 256 bits");
        }
        if (initNonce == null || 12 != initNonce.length) {
            throw new IllegalArgumentException("Nonce must be 96 bits");
        } else if (this.state == 0 || !forEncryption || !Arrays.areEqual(this.nonce, initNonce) || (initKeyParam != null && !Arrays.areEqual(this.key, initKeyParam.getKey()))) {
            if (initKeyParam != null) {
                System.arraycopy(initKeyParam.getKey(), 0, this.key, 0, 32);
            }
            System.arraycopy(initNonce, 0, this.nonce, 0, 12);
            this.chacha20.init(true, chacha20Params);
            this.state = forEncryption ? 1 : 5;
            reset(true, false);
        } else {
            throw new IllegalArgumentException("cannot reuse nonce for ChaCha20Poly1305 encryption");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getOutputSize(int len) {
        int total = Math.max(0, len) + this.bufPos;
        switch (this.state) {
            case 1:
            case 2:
            case 3:
                return total + 16;
            case 4:
            default:
                throw new IllegalStateException();
            case 5:
            case 6:
            case 7:
                return Math.max(0, total - 16);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getUpdateOutputSize(int len) {
        int total = Math.max(0, len) + this.bufPos;
        switch (this.state) {
            case 1:
            case 2:
            case 3:
                break;
            case 4:
            default:
                throw new IllegalStateException();
            case 5:
            case 6:
            case 7:
                total = Math.max(0, total - 16);
                break;
        }
        return total - (total % 64);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADByte(byte in) {
        checkAAD();
        this.aadCount = incrementCount(this.aadCount, 1, AAD_LIMIT);
        this.poly1305.update(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADBytes(byte[] in, int inOff, int len) {
        if (in == null) {
            throw new NullPointerException("'in' cannot be null");
        } else if (inOff < 0) {
            throw new IllegalArgumentException("'inOff' cannot be negative");
        } else if (len < 0) {
            throw new IllegalArgumentException("'len' cannot be negative");
        } else if (inOff > in.length - len) {
            throw new DataLengthException("Input buffer too short");
        } else {
            checkAAD();
            if (len > 0) {
                this.aadCount = incrementCount(this.aadCount, len, AAD_LIMIT);
                this.poly1305.update(in, inOff, len);
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processByte(byte in, byte[] out, int outOff) throws DataLengthException {
        checkData();
        switch (this.state) {
            case 3:
                this.buf[this.bufPos] = in;
                int i = this.bufPos + 1;
                this.bufPos = i;
                if (i != 64) {
                    return 0;
                }
                processData(this.buf, 0, 64, out, outOff);
                this.poly1305.update(out, outOff, 64);
                this.bufPos = 0;
                return 64;
            case 7:
                this.buf[this.bufPos] = in;
                int i2 = this.bufPos + 1;
                this.bufPos = i2;
                if (i2 != this.buf.length) {
                    return 0;
                }
                this.poly1305.update(this.buf, 0, 64);
                processData(this.buf, 0, 64, out, outOff);
                System.arraycopy(this.buf, 64, this.buf, 0, 16);
                this.bufPos = 16;
                return 64;
            default:
                throw new IllegalStateException();
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
        if (in == null) {
            throw new NullPointerException("'in' cannot be null");
        }
        if (out == null) {
        }
        if (inOff < 0) {
            throw new IllegalArgumentException("'inOff' cannot be negative");
        } else if (len < 0) {
            throw new IllegalArgumentException("'len' cannot be negative");
        } else if (inOff > in.length - len) {
            throw new DataLengthException("Input buffer too short");
        } else if (outOff < 0) {
            throw new IllegalArgumentException("'outOff' cannot be negative");
        } else {
            checkData();
            int resultLen = 0;
            switch (this.state) {
                case 3:
                    if (this.bufPos != 0) {
                        while (true) {
                            if (len > 0) {
                                len--;
                                inOff++;
                                this.buf[this.bufPos] = in[inOff];
                                int i = this.bufPos + 1;
                                this.bufPos = i;
                                if (i == 64) {
                                    processData(this.buf, 0, 64, out, outOff);
                                    this.poly1305.update(out, outOff, 64);
                                    this.bufPos = 0;
                                    resultLen = 64;
                                }
                            } else {
                                inOff = inOff;
                            }
                        }
                    }
                    while (len >= 64) {
                        processData(in, inOff, 64, out, outOff + resultLen);
                        this.poly1305.update(out, outOff + resultLen, 64);
                        inOff += 64;
                        len -= 64;
                        resultLen += 64;
                    }
                    if (len > 0) {
                        System.arraycopy(in, inOff, this.buf, 0, len);
                        this.bufPos = len;
                        break;
                    }
                    break;
                case 7:
                    for (int i2 = 0; i2 < len; i2++) {
                        this.buf[this.bufPos] = in[inOff + i2];
                        int i3 = this.bufPos + 1;
                        this.bufPos = i3;
                        if (i3 == this.buf.length) {
                            this.poly1305.update(this.buf, 0, 64);
                            processData(this.buf, 0, 64, out, outOff + resultLen);
                            System.arraycopy(this.buf, 64, this.buf, 0, 16);
                            this.bufPos = 16;
                            resultLen += 64;
                        }
                    }
                    break;
                default:
                    throw new IllegalStateException();
            }
            return resultLen;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int doFinal(byte[] out, int outOff) throws IllegalStateException, InvalidCipherTextException {
        int resultLen;
        if (out == null) {
            throw new NullPointerException("'out' cannot be null");
        } else if (outOff < 0) {
            throw new IllegalArgumentException("'outOff' cannot be negative");
        } else {
            checkData();
            Arrays.clear(this.mac);
            switch (this.state) {
                case 3:
                    resultLen = this.bufPos + 16;
                    if (outOff <= out.length - resultLen) {
                        if (this.bufPos > 0) {
                            processData(this.buf, 0, this.bufPos, out, outOff);
                            this.poly1305.update(out, outOff, this.bufPos);
                        }
                        finishData(4);
                        System.arraycopy(this.mac, 0, out, this.bufPos + outOff, 16);
                        break;
                    } else {
                        throw new OutputLengthException("Output buffer too short");
                    }
                case 7:
                    if (this.bufPos < 16) {
                        throw new InvalidCipherTextException("data too short");
                    }
                    resultLen = this.bufPos - 16;
                    if (outOff > out.length - resultLen) {
                        throw new OutputLengthException("Output buffer too short");
                    }
                    if (resultLen > 0) {
                        this.poly1305.update(this.buf, 0, resultLen);
                        processData(this.buf, 0, resultLen, out, outOff);
                    }
                    finishData(8);
                    if (!Arrays.constantTimeAreEqual(16, this.mac, 0, this.buf, resultLen)) {
                        throw new InvalidCipherTextException("mac check in ChaCha20Poly1305 failed");
                    }
                    break;
                default:
                    throw new IllegalStateException();
            }
            reset(false, true);
            return resultLen;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public byte[] getMac() {
        return Arrays.clone(this.mac);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void reset() {
        reset(true, true);
    }

    private void checkAAD() {
        switch (this.state) {
            case 1:
                this.state = 2;
                return;
            case 2:
            case 6:
                return;
            case 3:
            default:
                throw new IllegalStateException();
            case 4:
                throw new IllegalStateException("ChaCha20Poly1305 cannot be reused for encryption");
            case 5:
                this.state = 6;
                return;
        }
    }

    private void checkData() {
        switch (this.state) {
            case 1:
            case 2:
                finishAAD(3);
                return;
            case 3:
            case 7:
                return;
            case 4:
                throw new IllegalStateException("ChaCha20Poly1305 cannot be reused for encryption");
            case 5:
            case 6:
                finishAAD(7);
                return;
            default:
                throw new IllegalStateException();
        }
    }

    private void finishAAD(int nextState) {
        padMAC(this.aadCount);
        this.state = nextState;
    }

    private void finishData(int nextState) {
        padMAC(this.dataCount);
        byte[] lengths = new byte[16];
        Pack.longToLittleEndian(this.aadCount, lengths, 0);
        Pack.longToLittleEndian(this.dataCount, lengths, 8);
        this.poly1305.update(lengths, 0, 16);
        this.poly1305.doFinal(this.mac, 0);
        this.state = nextState;
    }

    private long incrementCount(long count, int increment, long limit) {
        if (count - Long.MIN_VALUE <= (limit - ((long) increment)) - Long.MIN_VALUE) {
            return ((long) increment) + count;
        }
        throw new IllegalStateException("Limit exceeded");
    }

    private void initMAC() {
        byte[] firstBlock = new byte[64];
        try {
            this.chacha20.processBytes(firstBlock, 0, 64, firstBlock, 0);
            this.poly1305.init(new KeyParameter(firstBlock, 0, 32));
        } finally {
            Arrays.clear(firstBlock);
        }
    }

    private void padMAC(long count) {
        int partial = ((int) count) & 15;
        if (partial != 0) {
            this.poly1305.update(ZEROES, 0, 16 - partial);
        }
    }

    private void processData(byte[] in, int inOff, int inLen, byte[] out, int outOff) {
        if (outOff > out.length - inLen) {
            throw new OutputLengthException("Output buffer too short");
        }
        this.chacha20.processBytes(in, inOff, inLen, out, outOff);
        this.dataCount = incrementCount(this.dataCount, inLen, DATA_LIMIT);
    }

    /* JADX INFO: Can't fix incorrect switch cases order, some code will duplicate */
    private void reset(boolean clearMac, boolean resetCipher) {
        Arrays.clear(this.buf);
        if (clearMac) {
            Arrays.clear(this.mac);
        }
        this.aadCount = 0;
        this.dataCount = 0;
        this.bufPos = 0;
        switch (this.state) {
            case 1:
            case 5:
                break;
            case 2:
            case 3:
            case 4:
                this.state = 4;
                return;
            case 6:
            case 7:
            case 8:
                this.state = 5;
                break;
            default:
                throw new IllegalStateException();
        }
        if (resetCipher) {
            this.chacha20.reset();
        }
        initMAC();
        if (this.initialAAD != null) {
            processAADBytes(this.initialAAD, 0, this.initialAAD.length);
        }
    }
}
