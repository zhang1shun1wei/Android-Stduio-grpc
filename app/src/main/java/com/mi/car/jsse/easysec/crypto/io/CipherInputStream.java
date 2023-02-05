package com.mi.car.jsse.easysec.crypto.io;

import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.SkippingCipher;
import com.mi.car.jsse.easysec.crypto.StreamCipher;
import com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class CipherInputStream extends FilterInputStream {
    private static final int INPUT_BUF_SIZE = 2048;
    private AEADBlockCipher aeadBlockCipher;
    private byte[] buf;
    private int bufOff;
    private BufferedBlockCipher bufferedBlockCipher;
    private boolean finalized;
    private byte[] inBuf;
    private byte[] markBuf;
    private int markBufOff;
    private long markPosition;
    private int maxBuf;
    private SkippingCipher skippingCipher;
    private StreamCipher streamCipher;

    public CipherInputStream(InputStream is, BufferedBlockCipher cipher) {
        this(is, cipher, 2048);
    }

    public CipherInputStream(InputStream is, StreamCipher cipher) {
        this(is, cipher, 2048);
    }

    public CipherInputStream(InputStream is, AEADBlockCipher cipher) {
        this(is, cipher, 2048);
    }

    public CipherInputStream(InputStream is, BufferedBlockCipher cipher, int bufSize) {
        super(is);
        this.bufferedBlockCipher = cipher;
        this.inBuf = new byte[bufSize];
        this.skippingCipher = cipher instanceof SkippingCipher ? (SkippingCipher) cipher : null;
    }

    public CipherInputStream(InputStream is, StreamCipher cipher, int bufSize) {
        super(is);
        this.streamCipher = cipher;
        this.inBuf = new byte[bufSize];
        this.skippingCipher = cipher instanceof SkippingCipher ? (SkippingCipher) cipher : null;
    }

    public CipherInputStream(InputStream is, AEADBlockCipher cipher, int bufSize) {
        super(is);
        this.aeadBlockCipher = cipher;
        this.inBuf = new byte[bufSize];
        this.skippingCipher = cipher instanceof SkippingCipher ? (SkippingCipher) cipher : null;
    }

    private int nextChunk() throws IOException {
        if (this.finalized) {
            return -1;
        }
        this.bufOff = 0;
        this.maxBuf = 0;
        while (this.maxBuf == 0) {
            int read = this.in.read(this.inBuf);
            if (read == -1) {
                finaliseCipher();
                if (this.maxBuf == 0) {
                    return -1;
                }
                return this.maxBuf;
            }
            try {
                ensureCapacity(read, false);
                if (this.bufferedBlockCipher != null) {
                    this.maxBuf = this.bufferedBlockCipher.processBytes(this.inBuf, 0, read, this.buf, 0);
                } else if (this.aeadBlockCipher != null) {
                    this.maxBuf = this.aeadBlockCipher.processBytes(this.inBuf, 0, read, this.buf, 0);
                } else {
                    this.streamCipher.processBytes(this.inBuf, 0, read, this.buf, 0);
                    this.maxBuf = read;
                }
            } catch (Exception e) {
                throw new CipherIOException("Error processing stream ", e);
            }
        }
        return this.maxBuf;
    }

    private void finaliseCipher() throws IOException {
        try {
            this.finalized = true;
            ensureCapacity(0, true);
            if (this.bufferedBlockCipher != null) {
                this.maxBuf = this.bufferedBlockCipher.doFinal(this.buf, 0);
            } else if (this.aeadBlockCipher != null) {
                this.maxBuf = this.aeadBlockCipher.doFinal(this.buf, 0);
            } else {
                this.maxBuf = 0;
            }
        } catch (InvalidCipherTextException e) {
            throw new InvalidCipherTextIOException("Error finalising cipher", e);
        } catch (Exception e2) {
            throw new IOException("Error finalising cipher " + e2);
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read() throws IOException {
        if (this.bufOff >= this.maxBuf && nextChunk() < 0) {
            return -1;
        }
        byte[] bArr = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        return bArr[i] & 255;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] b, int off, int len) throws IOException {
        if (this.bufOff >= this.maxBuf && nextChunk() < 0) {
            return -1;
        }
        int toSupply = Math.min(len, available());
        System.arraycopy(this.buf, this.bufOff, b, off, toSupply);
        this.bufOff += toSupply;
        return toSupply;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public long skip(long n) throws IOException {
        if (n <= 0) {
            return 0;
        }
        if (this.skippingCipher != null) {
            int avail = available();
            if (n <= ((long) avail)) {
                this.bufOff = (int) (((long) this.bufOff) + n);
                return n;
            }
            this.bufOff = this.maxBuf;
            long skip = this.in.skip(n - ((long) avail));
            if (skip == this.skippingCipher.skip(skip)) {
                return skip + ((long) avail);
            }
            throw new IOException("Unable to skip cipher " + skip + " bytes.");
        }
        int skip2 = (int) Math.min(n, (long) available());
        this.bufOff += skip2;
        return (long) skip2;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int available() throws IOException {
        return this.maxBuf - this.bufOff;
    }

    private void ensureCapacity(int updateSize, boolean finalOutput) {
        int bufLen = updateSize;
        if (finalOutput) {
            if (this.bufferedBlockCipher != null) {
                bufLen = this.bufferedBlockCipher.getOutputSize(updateSize);
            } else if (this.aeadBlockCipher != null) {
                bufLen = this.aeadBlockCipher.getOutputSize(updateSize);
            }
        } else if (this.bufferedBlockCipher != null) {
            bufLen = this.bufferedBlockCipher.getUpdateOutputSize(updateSize);
        } else if (this.aeadBlockCipher != null) {
            bufLen = this.aeadBlockCipher.getUpdateOutputSize(updateSize);
        }
        if (this.buf == null || this.buf.length < bufLen) {
            this.buf = new byte[bufLen];
        }
    }

    @Override // java.io.FilterInputStream, java.io.Closeable, java.lang.AutoCloseable, java.io.InputStream
    public void close() throws IOException {
        try {
            this.in.close();
            this.bufOff = 0;
            this.maxBuf = 0;
            this.markBufOff = 0;
            this.markPosition = 0;
            if (this.markBuf != null) {
                Arrays.fill(this.markBuf, (byte) 0);
                this.markBuf = null;
            }
            if (this.buf != null) {
                Arrays.fill(this.buf, (byte) 0);
                this.buf = null;
            }
            Arrays.fill(this.inBuf, (byte) 0);
        } finally {
            if (!this.finalized) {
                finaliseCipher();
            }
        }
    }

    public void mark(int readlimit) {
        this.in.mark(readlimit);
        if (this.skippingCipher != null) {
            this.markPosition = this.skippingCipher.getPosition();
        }
        if (this.buf != null) {
            this.markBuf = new byte[this.buf.length];
            System.arraycopy(this.buf, 0, this.markBuf, 0, this.buf.length);
        }
        this.markBufOff = this.bufOff;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public void reset() throws IOException {
        if (this.skippingCipher == null) {
            throw new IOException("cipher must implement SkippingCipher to be used with reset()");
        }
        this.in.reset();
        this.skippingCipher.seekTo(this.markPosition);
        if (this.markBuf != null) {
            this.buf = this.markBuf;
        }
        this.bufOff = this.markBufOff;
    }

    public boolean markSupported() {
        if (this.skippingCipher != null) {
            return this.in.markSupported();
        }
        return false;
    }
}
