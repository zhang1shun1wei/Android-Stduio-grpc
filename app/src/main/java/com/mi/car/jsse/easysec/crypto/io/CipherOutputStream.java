package com.mi.car.jsse.easysec.crypto.io;

import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.StreamCipher;
import com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class CipherOutputStream extends FilterOutputStream {
    private AEADBlockCipher aeadBlockCipher;
    private byte[] buf;
    private BufferedBlockCipher bufferedBlockCipher;
    private final byte[] oneByte;
    private StreamCipher streamCipher;

    public CipherOutputStream(OutputStream os, BufferedBlockCipher cipher) {
        super(os);
        this.oneByte = new byte[1];
        this.bufferedBlockCipher = cipher;
    }

    public CipherOutputStream(OutputStream os, StreamCipher cipher) {
        super(os);
        this.oneByte = new byte[1];
        this.streamCipher = cipher;
    }

    public CipherOutputStream(OutputStream os, AEADBlockCipher cipher) {
        super(os);
        this.oneByte = new byte[1];
        this.aeadBlockCipher = cipher;
    }

    @Override // java.io.OutputStream, java.io.FilterOutputStream
    public void write(int b) throws IOException {
        this.oneByte[0] = (byte) b;
        if (this.streamCipher != null) {
            this.out.write(this.streamCipher.returnByte((byte) b));
        } else {
            write(this.oneByte, 0, 1);
        }
    }

    @Override // java.io.OutputStream, java.io.FilterOutputStream
    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    @Override // java.io.OutputStream, java.io.FilterOutputStream
    public void write(byte[] b, int off, int len) throws IOException {
        ensureCapacity(len, false);
        if (this.bufferedBlockCipher != null) {
            int outLen = this.bufferedBlockCipher.processBytes(b, off, len, this.buf, 0);
            if (outLen != 0) {
                this.out.write(this.buf, 0, outLen);
            }
        } else if (this.aeadBlockCipher != null) {
            int outLen2 = this.aeadBlockCipher.processBytes(b, off, len, this.buf, 0);
            if (outLen2 != 0) {
                this.out.write(this.buf, 0, outLen2);
            }
        } else {
            this.streamCipher.processBytes(b, off, len, this.buf, 0);
            this.out.write(this.buf, 0, len);
        }
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

    @Override // java.io.OutputStream, java.io.FilterOutputStream, java.io.Flushable
    public void flush() throws IOException {
        this.out.flush();
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.io.FilterOutputStream, java.lang.AutoCloseable
    public void close() throws IOException {
        ensureCapacity(0, true);
        IOException error = null;
        try {
            if (this.bufferedBlockCipher != null) {
                int outLen = this.bufferedBlockCipher.doFinal(this.buf, 0);
                if (outLen != 0) {
                    this.out.write(this.buf, 0, outLen);
                }
            } else if (this.aeadBlockCipher != null) {
                int outLen2 = this.aeadBlockCipher.doFinal(this.buf, 0);
                if (outLen2 != 0) {
                    this.out.write(this.buf, 0, outLen2);
                }
            } else if (this.streamCipher != null) {
                this.streamCipher.reset();
            }
        } catch (InvalidCipherTextException e) {
            error = new InvalidCipherTextIOException("Error finalising cipher data", e);
        } catch (Exception e2) {
            error = new CipherIOException("Error closing stream: ", e2);
        }
        try {
            flush();
            this.out.close();
        } catch (IOException e3) {
            if (error == null) {
                error = e3;
            }
        }
        if (error != null) {
            throw error;
        }
    }
}
