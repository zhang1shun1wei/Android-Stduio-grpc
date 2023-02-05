package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class JournalingSecureRandom extends SecureRandom {
    private static byte[] EMPTY_TRANSCRIPT = new byte[0];
    private final SecureRandom base;
    private int index;
    private TranscriptStream tOut;
    private byte[] transcript;

    public JournalingSecureRandom() {
        this(CryptoServicesRegistrar.getSecureRandom());
    }

    public JournalingSecureRandom(SecureRandom random) {
        this.tOut = new TranscriptStream();
        this.index = 0;
        this.base = random;
        this.transcript = EMPTY_TRANSCRIPT;
    }

    public JournalingSecureRandom(byte[] transcript2, SecureRandom random) {
        this.tOut = new TranscriptStream();
        this.index = 0;
        this.base = random;
        this.transcript = Arrays.clone(transcript2);
    }

    public final void nextBytes(byte[] bytes) {
        if (this.index >= this.transcript.length) {
            this.base.nextBytes(bytes);
        } else {
            int i = 0;
            while (i != bytes.length && this.index < this.transcript.length) {
                byte[] bArr = this.transcript;
                int i2 = this.index;
                this.index = i2 + 1;
                bytes[i] = bArr[i2];
                i++;
            }
            if (i != bytes.length) {
                byte[] extra = new byte[(bytes.length - i)];
                this.base.nextBytes(extra);
                System.arraycopy(extra, 0, bytes, i, extra.length);
            }
        }
        try {
            this.tOut.write(bytes);
        } catch (IOException e) {
            throw new IllegalStateException("unable to record transcript: " + e.getMessage());
        }
    }

    public void clear() {
        Arrays.fill(this.transcript, (byte) 0);
        this.tOut.clear();
    }

    public void reset() {
        this.index = 0;
        if (this.index == this.transcript.length) {
            this.transcript = this.tOut.toByteArray();
        }
        this.tOut.reset();
    }

    public byte[] getTranscript() {
        return this.tOut.toByteArray();
    }

    public byte[] getFullTranscript() {
        if (this.index == this.transcript.length) {
            return this.tOut.toByteArray();
        }
        return Arrays.clone(this.transcript);
    }

    private class TranscriptStream extends ByteArrayOutputStream {
        private TranscriptStream() {
        }

        public void clear() {
            Arrays.fill(this.buf, (byte) 0);
        }
    }
}
