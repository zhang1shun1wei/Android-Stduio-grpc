//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCipher;
import com.mi.car.jsse.easysec.tls.crypto.TlsDecodeResult;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncodeResult;
import com.mi.car.jsse.easysec.tls.crypto.TlsNullNullCipher;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;

class RecordStream {
    private static int DEFAULT_PLAINTEXT_LIMIT = 16384;
    private final RecordStream.Record inputRecord = new RecordStream.Record();
    private final RecordStream.SequenceNumber readSeqNo = new RecordStream.SequenceNumber();
    private final RecordStream.SequenceNumber writeSeqNo = new RecordStream.SequenceNumber();
    private TlsProtocol handler;
    private InputStream input;
    private OutputStream output;
    private TlsCipher pendingCipher = null;
    private TlsCipher readCipher;
    private TlsCipher readCipherDeferred;
    private TlsCipher writeCipher;
    private ProtocolVersion writeVersion;
    private int plaintextLimit;
    private int ciphertextLimit;
    private boolean ignoreChangeCipherSpec;

    RecordStream(TlsProtocol handler, InputStream input, OutputStream output) {
        this.readCipher = TlsNullNullCipher.INSTANCE;
        this.readCipherDeferred = null;
        this.writeCipher = TlsNullNullCipher.INSTANCE;
        this.writeVersion = null;
        this.plaintextLimit = DEFAULT_PLAINTEXT_LIMIT;
        this.ciphertextLimit = DEFAULT_PLAINTEXT_LIMIT;
        this.ignoreChangeCipherSpec = false;
        this.handler = handler;
        this.input = input;
        this.output = output;
    }

    int getPlaintextLimit() {
        return this.plaintextLimit;
    }

    void setPlaintextLimit(int plaintextLimit) {
        this.plaintextLimit = plaintextLimit;
        this.ciphertextLimit = this.readCipher.getCiphertextDecodeLimit(plaintextLimit);
    }

    void setWriteVersion(ProtocolVersion writeVersion) {
        this.writeVersion = writeVersion;
    }

    void setIgnoreChangeCipherSpec(boolean ignoreChangeCipherSpec) {
        this.ignoreChangeCipherSpec = ignoreChangeCipherSpec;
    }

    void setPendingCipher(TlsCipher tlsCipher) {
        this.pendingCipher = tlsCipher;
    }

    void notifyChangeCipherSpecReceived() throws IOException {
        if (this.pendingCipher == null) {
            throw new TlsFatalAlert((short)10, "No pending cipher");
        } else {
            this.enablePendingCipherRead(false);
        }
    }

    void enablePendingCipherRead(boolean deferred) throws IOException {
        if (this.pendingCipher == null) {
            throw new TlsFatalAlert((short)80);
        } else if (this.readCipherDeferred != null) {
            throw new TlsFatalAlert((short)80);
        } else {
            if (deferred) {
                this.readCipherDeferred = this.pendingCipher;
            } else {
                this.readCipher = this.pendingCipher;
                this.ciphertextLimit = this.readCipher.getCiphertextDecodeLimit(this.plaintextLimit);
                this.readSeqNo.reset();
            }

        }
    }

    void enablePendingCipherWrite() throws IOException {
        if (this.pendingCipher == null) {
            throw new TlsFatalAlert((short)80);
        } else {
            this.writeCipher = this.pendingCipher;
            this.writeSeqNo.reset();
        }
    }

    void finaliseHandshake() throws IOException {
        if (this.readCipher == this.pendingCipher && this.writeCipher == this.pendingCipher) {
            this.pendingCipher = null;
        } else {
            throw new TlsFatalAlert((short)40);
        }
    }

    boolean needsKeyUpdate() {
        return this.writeSeqNo.currentValue() >= 1048576L;
    }

    void notifyKeyUpdateReceived() throws IOException {
        this.readCipher.rekeyDecoder();
        this.readSeqNo.reset();
    }

    void notifyKeyUpdateSent() throws IOException {
        this.writeCipher.rekeyEncoder();
        this.writeSeqNo.reset();
    }

    RecordPreview previewRecordHeader(byte[] recordHeader) throws IOException {
        short recordType = this.checkRecordType(recordHeader, 0);
        int length = TlsUtils.readUint16(recordHeader, 3);
        checkLength(length, this.ciphertextLimit, (short)22);
        int recordSize = 5 + length;
        int applicationDataLimit = 0;
        if (23 == recordType && this.handler.isApplicationDataReady()) {
            applicationDataLimit = Math.max(0, Math.min(this.plaintextLimit, this.readCipher.getPlaintextLimit(length)));
        }

        return new RecordPreview(recordSize, applicationDataLimit);
    }

    RecordPreview previewOutputRecord(int contentLength) {
        int contentLimit = Math.max(0, Math.min(this.plaintextLimit, contentLength));
        int recordSize = this.previewOutputRecordSize(contentLimit);
        return new RecordPreview(recordSize, contentLimit);
    }

    int previewOutputRecordSize(int contentLength) {
        return 5 + this.writeCipher.getCiphertextEncodeLimit(contentLength, this.plaintextLimit);
    }

    boolean readFullRecord(byte[] input, int inputOff, int inputLen) throws IOException {
        if (inputLen < 5) {
            return false;
        } else {
            int length = TlsUtils.readUint16(input, inputOff + 3);
            if (inputLen != 5 + length) {
                return false;
            } else {
                short recordType = this.checkRecordType(input, inputOff + 0);
                ProtocolVersion recordVersion = TlsUtils.readVersion(input, inputOff + 1);
                checkLength(length, this.ciphertextLimit, (short)22);
                if (this.ignoreChangeCipherSpec && 20 == recordType) {
                    this.checkChangeCipherSpec(input, inputOff + 5, length);
                    return true;
                } else {
                    TlsDecodeResult decoded = this.decodeAndVerify(recordType, recordVersion, input, inputOff + 5, length);
                    this.handler.processRecord(decoded.contentType, decoded.buf, decoded.off, decoded.len);
                    return true;
                }
            }
        }
    }

    boolean readRecord() throws IOException {
        if (!this.inputRecord.readHeader(this.input)) {
            return false;
        } else {
            short recordType = this.checkRecordType(this.inputRecord.buf, 0);
            ProtocolVersion recordVersion = TlsUtils.readVersion(this.inputRecord.buf, 1);
            int length = TlsUtils.readUint16(this.inputRecord.buf, 3);
            checkLength(length, this.ciphertextLimit, (short)22);
            this.inputRecord.readFragment(this.input, length);

            TlsDecodeResult decoded;
            try {
                if (this.ignoreChangeCipherSpec && 20 == recordType) {
                    this.checkChangeCipherSpec(this.inputRecord.buf, 5, length);
                    boolean var5 = true;
                    return var5;
                }

                decoded = this.decodeAndVerify(recordType, recordVersion, this.inputRecord.buf, 5, length);
            } finally {
                this.inputRecord.reset();
            }

            this.handler.processRecord(decoded.contentType, decoded.buf, decoded.off, decoded.len);
            return true;
        }
    }

    TlsDecodeResult decodeAndVerify(short recordType, ProtocolVersion recordVersion, byte[] ciphertext, int off, int len) throws IOException {
        long seqNo = this.readSeqNo.nextValue((short)10);
        TlsDecodeResult decoded = this.readCipher.decodeCiphertext(seqNo, recordType, recordVersion, ciphertext, off, len);
        checkLength(decoded.len, this.plaintextLimit, (short)22);
        if (decoded.len < 1 && decoded.contentType != 23) {
            throw new TlsFatalAlert((short)47);
        } else {
            return decoded;
        }
    }

    void writeRecord(short contentType, byte[] plaintext, int plaintextOffset, int plaintextLength) throws IOException {
        if (this.writeVersion != null) {
            checkLength(plaintextLength, this.plaintextLimit, (short)80);
            if (plaintextLength < 1 && contentType != 23) {
                throw new TlsFatalAlert((short)80);
            } else {
                long seqNo = this.writeSeqNo.nextValue((short)80);
                ProtocolVersion recordVersion = this.writeVersion;
                TlsEncodeResult encoded = this.writeCipher.encodePlaintext(seqNo, contentType, recordVersion, 5, plaintext, plaintextOffset, plaintextLength);
                int ciphertextLength = encoded.len - 5;
                TlsUtils.checkUint16(ciphertextLength);
                TlsUtils.writeUint8(encoded.recordType, encoded.buf, encoded.off + 0);
                TlsUtils.writeVersion(recordVersion, encoded.buf, encoded.off + 1);
                TlsUtils.writeUint16(ciphertextLength, encoded.buf, encoded.off + 3);

                try {
                    this.output.write(encoded.buf, encoded.off, encoded.len);
                } catch (InterruptedIOException var11) {
                    throw new TlsFatalAlert((short)80, var11);
                }

                this.output.flush();
            }
        }
    }

    void close() throws IOException {
        this.inputRecord.reset();
        IOException io = null;

        try {
            this.input.close();
        } catch (IOException var3) {
            io = var3;
        }

        try {
            this.output.close();
        } catch (IOException var4) {
            if (io == null) {
                io = var4;
            }
        }

        if (io != null) {
            throw io;
        }
    }

    private void checkChangeCipherSpec(byte[] buf, int off, int len) throws IOException {
        if (1 != len || 1 != buf[off]) {
            throw new TlsFatalAlert((short)10, "Malformed " + ContentType.getText((short)20));
        }
    }

    private short checkRecordType(byte[] buf, int off) throws IOException {
        short recordType = TlsUtils.readUint8(buf, off);
        if (null != this.readCipherDeferred && recordType == 23) {
            this.readCipher = this.readCipherDeferred;
            this.readCipherDeferred = null;
            this.ciphertextLimit = this.readCipher.getCiphertextDecodeLimit(this.plaintextLimit);
            this.readSeqNo.reset();
        } else if (this.readCipher.usesOpaqueRecordType()) {
            if (23 != recordType && (!this.ignoreChangeCipherSpec || 20 != recordType)) {
                throw new TlsFatalAlert((short)10, "Opaque " + ContentType.getText(recordType));
            }
        } else {
            switch(recordType) {
                case 20:
                case 21:
                case 22:
                    break;
                case 23:
                    if (!this.handler.isApplicationDataReady()) {
                        throw new TlsFatalAlert((short)10, "Not ready for " + ContentType.getText((short)23));
                    }
                    break;
                default:
                    throw new TlsFatalAlert((short)10, "Unsupported " + ContentType.getText(recordType));
            }
        }

        return recordType;
    }

    private static void checkLength(int length, int limit, short alertDescription) throws IOException {
        if (length > limit) {
            throw new TlsFatalAlert(alertDescription);
        }
    }

    private static class SequenceNumber {
        private long value;
        private boolean exhausted;

        private SequenceNumber() {
            this.value = 0L;
            this.exhausted = false;
        }

        synchronized long currentValue() {
            return this.value;
        }

        synchronized long nextValue(short alertDescription) throws TlsFatalAlert {
            if (this.exhausted) {
                throw new TlsFatalAlert(alertDescription, "Sequence numbers exhausted");
            } else {
                long result = this.value;
                if (++this.value == 0L) {
                    this.exhausted = true;
                }

                return result;
            }
        }

        synchronized void reset() {
            this.value = 0L;
            this.exhausted = false;
        }
    }

    private static class Record {
        private final byte[] header;
        volatile byte[] buf;
        volatile int pos;

        private Record() {
            this.header = new byte[5];
            this.buf = this.header;
            this.pos = 0;
        }

        void fillTo(InputStream input, int length) throws IOException {
            while(true) {
                if (this.pos < length) {
                    try {
                        int numRead = input.read(this.buf, this.pos, length - this.pos);
                        if (numRead >= 0) {
                            this.pos += numRead;
                            continue;
                        }
                    } catch (InterruptedIOException var4) {
                        this.pos += var4.bytesTransferred;
                        var4.bytesTransferred = 0;
                        throw var4;
                    }
                }

                return;
            }
        }

        void readFragment(InputStream input, int fragmentLength) throws IOException {
            int recordLength = 5 + fragmentLength;
            this.resize(recordLength);
            this.fillTo(input, recordLength);
            if (this.pos < recordLength) {
                throw new EOFException();
            }
        }

        boolean readHeader(InputStream input) throws IOException {
            this.fillTo(input, 5);
            if (this.pos == 0) {
                return false;
            } else if (this.pos < 5) {
                throw new EOFException();
            } else {
                return true;
            }
        }

        void reset() {
            this.buf = this.header;
            this.pos = 0;
        }

        private void resize(int length) {
            if (this.buf.length < length) {
                byte[] tmp = new byte[length];
                System.arraycopy(this.buf, 0, tmp, 0, this.pos);
                this.buf = tmp;
            }

        }
    }
}