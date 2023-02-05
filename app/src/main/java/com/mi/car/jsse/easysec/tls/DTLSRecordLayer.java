package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCipher;
import com.mi.car.jsse.easysec.tls.crypto.TlsDecodeResult;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncodeResult;
import com.mi.car.jsse.easysec.tls.crypto.TlsNullNullCipher;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;


class DTLSRecordLayer implements DatagramTransport {
    private static final int RECORD_HEADER_LENGTH = 13;
    private static final int MAX_FRAGMENT_LENGTH = 16384;
    private static final long TCP_MSL = 120000L;
    private static final long RETRANSMIT_TIMEOUT = 240000L;
    private final TlsContext context;
    private final TlsPeer peer;
    private final DatagramTransport transport;
    private final ByteQueue recordQueue = new ByteQueue();
    private final Object writeLock = new Object();
    private volatile boolean closed = false;
    private volatile boolean failed = false;
    private volatile ProtocolVersion readVersion = null;
    private volatile ProtocolVersion writeVersion = null;
    private volatile boolean inConnection;
    private volatile boolean inHandshake;
    private volatile int plaintextLimit;
    private DTLSEpoch currentEpoch;
    private DTLSEpoch pendingEpoch;
    private DTLSEpoch readEpoch;
    private DTLSEpoch writeEpoch;
    private DTLSHandshakeRetransmit retransmit = null;
    private DTLSEpoch retransmitEpoch = null;
    private Timeout retransmitTimeout = null;
    private TlsHeartbeat heartbeat = null;
    private boolean heartBeatResponder = false;
    private HeartbeatMessage heartbeatInFlight = null;
    private Timeout heartbeatTimeout = null;
    private int heartbeatResendMillis = -1;
    private Timeout heartbeatResendTimeout = null;

    static byte[] receiveClientHelloRecord(byte[] data, int dataOff, int dataLen) throws IOException {
        if (dataLen < 13) {
            return null;
        } else {
            short contentType = TlsUtils.readUint8(data, dataOff + 0);
            if (22 != contentType) {
                return null;
            } else {
                ProtocolVersion version = TlsUtils.readVersion(data, dataOff + 1);
                if (!ProtocolVersion.DTLSv10.isEqualOrEarlierVersionOf(version)) {
                    return null;
                } else {
                    int epoch = TlsUtils.readUint16(data, dataOff + 3);
                    if (0 != epoch) {
                        return null;
                    } else {
                        int length = TlsUtils.readUint16(data, dataOff + 11);
                        if (dataLen < 13 + length) {
                            return null;
                        } else {
                            return length > 16384 ? null : TlsUtils.copyOfRangeExact(data, dataOff + 13, dataOff + 13 + length);
                        }
                    }
                }
            }
        }
    }

    static void sendHelloVerifyRequestRecord(DatagramSender sender, long recordSeq, byte[] message) throws IOException {
        TlsUtils.checkUint16(message.length);
        byte[] record = new byte[13 + message.length];
        TlsUtils.writeUint8((short)22, record, 0);
        TlsUtils.writeVersion(ProtocolVersion.DTLSv10, record, 1);
        TlsUtils.writeUint16(0, record, 3);
        TlsUtils.writeUint48(recordSeq, record, 5);
        TlsUtils.writeUint16(message.length, record, 11);
        System.arraycopy(message, 0, record, 13, message.length);
        sendDatagram(sender, record, 0, record.length);
    }

    private static void sendDatagram(DatagramSender sender, byte[] buf, int off, int len) throws IOException {
        try {
            sender.send(buf, off, len);
        } catch (InterruptedIOException var5) {
            var5.bytesTransferred = 0;
            throw var5;
        }
    }

    DTLSRecordLayer(TlsContext context, TlsPeer peer, DatagramTransport transport) {
        this.context = context;
        this.peer = peer;
        this.transport = transport;
        this.inHandshake = true;
        this.currentEpoch = new DTLSEpoch(0, TlsNullNullCipher.INSTANCE);
        this.pendingEpoch = null;
        this.readEpoch = this.currentEpoch;
        this.writeEpoch = this.currentEpoch;
        this.setPlaintextLimit(16384);
    }

    boolean isClosed() {
        return this.closed;
    }

    void resetAfterHelloVerifyRequestServer(long recordSeq) {
        this.inConnection = true;
        this.currentEpoch.setSequenceNumber(recordSeq);
        this.currentEpoch.getReplayWindow().reset(recordSeq);
    }

    void setPlaintextLimit(int plaintextLimit) {
        this.plaintextLimit = plaintextLimit;
    }

    int getReadEpoch() {
        return this.readEpoch.getEpoch();
    }

    ProtocolVersion getReadVersion() {
        return this.readVersion;
    }

    void setReadVersion(ProtocolVersion readVersion) {
        this.readVersion = readVersion;
    }

    void setWriteVersion(ProtocolVersion writeVersion) {
        this.writeVersion = writeVersion;
    }

    void initPendingEpoch(TlsCipher pendingCipher) {
        if (this.pendingEpoch != null) {
            throw new IllegalStateException();
        } else {
            this.pendingEpoch = new DTLSEpoch(this.writeEpoch.getEpoch() + 1, pendingCipher);
        }
    }

    void handshakeSuccessful(DTLSHandshakeRetransmit retransmit) {
        if (this.readEpoch != this.currentEpoch && this.writeEpoch != this.currentEpoch) {
            if (null != retransmit) {
                this.retransmit = retransmit;
                this.retransmitEpoch = this.currentEpoch;
                this.retransmitTimeout = new Timeout(240000L);
            }

            this.inHandshake = false;
            this.currentEpoch = this.pendingEpoch;
            this.pendingEpoch = null;
        } else {
            throw new IllegalStateException();
        }
    }

    void initHeartbeat(TlsHeartbeat heartbeat, boolean heartbeatResponder) {
        if (this.inHandshake) {
            throw new IllegalStateException();
        } else {
            this.heartbeat = heartbeat;
            this.heartBeatResponder = heartbeatResponder;
            if (null != heartbeat) {
                this.resetHeartbeat();
            }

        }
    }

    void resetWriteEpoch() {
        if (null != this.retransmitEpoch) {
            this.writeEpoch = this.retransmitEpoch;
        } else {
            this.writeEpoch = this.currentEpoch;
        }

    }

    public int getReceiveLimit() throws IOException {
        return Math.min(this.plaintextLimit, this.readEpoch.getCipher().getPlaintextLimit(this.transport.getReceiveLimit() - 13));
    }

    public int getSendLimit() throws IOException {
        return Math.min(this.plaintextLimit, this.writeEpoch.getCipher().getPlaintextLimit(this.transport.getSendLimit() - 13));
    }

    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
        long currentTimeMillis = System.currentTimeMillis();
        Timeout timeout = Timeout.forWaitMillis(waitMillis, currentTimeMillis);

        for(byte[] record = null; waitMillis >= 0; waitMillis = Timeout.getWaitMillis(timeout, currentTimeMillis)) {
            if (null != this.retransmitTimeout && this.retransmitTimeout.remainingMillis(currentTimeMillis) < 1L) {
                this.retransmit = null;
                this.retransmitEpoch = null;
                this.retransmitTimeout = null;
            }

            if (Timeout.hasExpired(this.heartbeatTimeout, currentTimeMillis)) {
                if (null != this.heartbeatInFlight) {
                    throw new TlsTimeoutException("Heartbeat timed out");
                }

                this.heartbeatInFlight = HeartbeatMessage.create(this.context, (short)1, this.heartbeat.generatePayload());
                this.heartbeatTimeout = new Timeout((long)this.heartbeat.getTimeoutMillis(), currentTimeMillis);
                this.heartbeatResendMillis = 1000;
                this.heartbeatResendTimeout = new Timeout((long)this.heartbeatResendMillis, currentTimeMillis);
                this.sendHeartbeatMessage(this.heartbeatInFlight);
            } else if (Timeout.hasExpired(this.heartbeatResendTimeout, currentTimeMillis)) {
                this.heartbeatResendMillis = DTLSReliableHandshake.backOff(this.heartbeatResendMillis);
                this.heartbeatResendTimeout = new Timeout((long)this.heartbeatResendMillis, currentTimeMillis);
                this.sendHeartbeatMessage(this.heartbeatInFlight);
            }

            waitMillis = Timeout.constrainWaitMillis(waitMillis, this.heartbeatTimeout, currentTimeMillis);
            waitMillis = Timeout.constrainWaitMillis(waitMillis, this.heartbeatResendTimeout, currentTimeMillis);
            if (waitMillis < 0) {
                waitMillis = 1;
            }

            int receiveLimit = Math.min(len, this.getReceiveLimit()) + 13;
            if (null == record || record.length < receiveLimit) {
                record = new byte[receiveLimit];
            }

            int received = this.receiveRecord(record, 0, receiveLimit, waitMillis);
            int processed = this.processRecord(received, record, buf, off);
            if (processed >= 0) {
                return processed;
            }

            currentTimeMillis = System.currentTimeMillis();
        }

        return -1;
    }

    public void send(byte[] buf, int off, int len) throws IOException {
        short contentType = 23;
        if (this.inHandshake || this.writeEpoch == this.retransmitEpoch) {
            contentType = 22;
            short handshakeType = TlsUtils.readUint8(buf, off);
            if (handshakeType == 20) {
                DTLSEpoch nextEpoch = null;
                if (this.inHandshake) {
                    nextEpoch = this.pendingEpoch;
                } else if (this.writeEpoch == this.retransmitEpoch) {
                    nextEpoch = this.currentEpoch;
                }

                if (nextEpoch == null) {
                    throw new IllegalStateException();
                }

                byte[] data = new byte[]{1};
                this.sendRecord((short)20, data, 0, data.length);
                this.writeEpoch = nextEpoch;
            }
        }

        this.sendRecord(contentType, buf, off, len);
    }

    public void close() throws IOException {
        if (!this.closed) {
            if (this.inHandshake && this.inConnection) {
                this.warn((short)90, "User canceled handshake");
            }

            this.closeTransport();
        }

    }

    void fail(short alertDescription) {
        if (!this.closed) {
            if (this.inConnection) {
                try {
                    this.raiseAlert((short)2, alertDescription, (String)null, (Throwable)null);
                } catch (Exception var3) {
                }
            }

            this.failed = true;
            this.closeTransport();
        }

    }

    void failed() {
        if (!this.closed) {
            this.failed = true;
            this.closeTransport();
        }

    }

    void warn(short alertDescription, String message) throws IOException {
        this.raiseAlert((short)1, alertDescription, message, (Throwable)null);
    }

    private void closeTransport() {
        if (!this.closed) {
            try {
                if (!this.failed) {
                    this.warn((short)0, (String)null);
                }

                this.transport.close();
            } catch (Exception var2) {
            }

            this.closed = true;
        }

    }

    private void raiseAlert(short alertLevel, short alertDescription, String message, Throwable cause) throws IOException {
        this.peer.notifyAlertRaised(alertLevel, alertDescription, message, cause);
        byte[] error = new byte[]{(byte)alertLevel, (byte)alertDescription};
        this.sendRecord((short)21, error, 0, 2);
    }

    private int receiveDatagram(byte[] buf, int off, int len, int waitMillis) throws IOException {
        try {
            return this.transport.receive(buf, off, len, waitMillis);
        } catch (SocketTimeoutException var6) {
            return -1;
        } catch (InterruptedIOException var7) {
            var7.bytesTransferred = 0;
            throw var7;
        }
    }

    private int processRecord(int received, byte[] record, byte[] buf, int off) throws IOException {
        if (received < 13) {
            return -1;
        } else {
            int length = TlsUtils.readUint16(record, 11);
            if (received != length + 13) {
                return -1;
            } else {
                short recordType = TlsUtils.readUint8(record, 0);
                switch(recordType) {
                    case 20:
                    case 21:
                    case 22:
                    case 23:
                    case 24:
                        int epoch = TlsUtils.readUint16(record, 3);
                        DTLSEpoch recordEpoch = null;
                        if (epoch == this.readEpoch.getEpoch()) {
                            recordEpoch = this.readEpoch;
                        } else if (recordType == 22 && null != this.retransmitEpoch && epoch == this.retransmitEpoch.getEpoch()) {
                            recordEpoch = this.retransmitEpoch;
                        }

                        if (null == recordEpoch) {
                            return -1;
                        } else {
                            long seq = TlsUtils.readUint48(record, 5);
                            if (recordEpoch.getReplayWindow().shouldDiscard(seq)) {
                                return -1;
                            } else {
                                ProtocolVersion recordVersion = TlsUtils.readVersion(record, 1);
                                if (!recordVersion.isDTLS()) {
                                    return -1;
                                } else {
                                    if (null != this.readVersion && !this.readVersion.equals(recordVersion)) {
                                        boolean isClientHelloFragment = this.getReadEpoch() == 0 && length > 0 && 22 == recordType && 1 == TlsUtils.readUint8(record, 13);
                                        if (!isClientHelloFragment) {
                                            return -1;
                                        }
                                    }

                                    long macSeqNo = getMacSequenceNumber(recordEpoch.getEpoch(), seq);
                                    TlsDecodeResult decoded = recordEpoch.getCipher().decodeCiphertext(macSeqNo, recordType, recordVersion, record, 13, length);
                                    recordEpoch.getReplayWindow().reportAuthenticated(seq);
                                    if (decoded.len > this.plaintextLimit) {
                                        return -1;
                                    } else if (decoded.len < 1 && decoded.contentType != 23) {
                                        return -1;
                                    } else {
                                        if (null == this.readVersion) {
                                            boolean isHelloVerifyRequest = this.getReadEpoch() == 0 && length > 0 && 22 == recordType && 3 == TlsUtils.readUint8(record, 13);
                                            if (isHelloVerifyRequest) {
                                                if (!ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(recordVersion)) {
                                                    return -1;
                                                }
                                            } else {
                                                this.readVersion = recordVersion;
                                            }
                                        }

                                        short alertDescription;
                                        switch(decoded.contentType) {
                                            case 20:
                                                for(int i = 0; i < decoded.len; ++i) {
                                                    alertDescription = TlsUtils.readUint8(decoded.buf, decoded.off + i);
                                                    if (alertDescription == 1 && this.pendingEpoch != null) {
                                                        this.readEpoch = this.pendingEpoch;
                                                    }
                                                }

                                                return -1;
                                            case 21:
                                                if (decoded.len == 2) {
                                                    short alertLevel = TlsUtils.readUint8(decoded.buf, decoded.off);
                                                    alertDescription = TlsUtils.readUint8(decoded.buf, decoded.off + 1);
                                                    this.peer.notifyAlertReceived(alertLevel, alertDescription);
                                                    if (alertLevel == 2) {
                                                        this.failed();
                                                        throw new TlsFatalAlert(alertDescription);
                                                    }

                                                    if (alertDescription == 0) {
                                                        this.closeTransport();
                                                    }
                                                }

                                                return -1;
                                            case 22:
                                                if (!this.inHandshake) {
                                                    if (null != this.retransmit) {
                                                        this.retransmit.receivedHandshakeRecord(epoch, decoded.buf, decoded.off, decoded.len);
                                                    }

                                                    return -1;
                                                }
                                                break;
                                            case 23:
                                                if (this.inHandshake) {
                                                    return -1;
                                                }
                                                break;
                                            case 24:
                                                if (null != this.heartbeatInFlight || this.heartBeatResponder) {
                                                    try {
                                                        ByteArrayInputStream input = new ByteArrayInputStream(decoded.buf, decoded.off, decoded.len);
                                                        HeartbeatMessage heartbeatMessage = HeartbeatMessage.parse(input);
                                                        if (null != heartbeatMessage) {
                                                            switch(heartbeatMessage.getType()) {
                                                                case 1:
                                                                    if (this.heartBeatResponder) {
                                                                        HeartbeatMessage response = HeartbeatMessage.create(this.context, (short)2, heartbeatMessage.getPayload());
                                                                        this.sendHeartbeatMessage(response);
                                                                    }
                                                                    break;
                                                                case 2:
                                                                    if (null != this.heartbeatInFlight && Arrays.areEqual(heartbeatMessage.getPayload(), this.heartbeatInFlight.getPayload())) {
                                                                        this.resetHeartbeat();
                                                                    }
                                                            }
                                                        }
                                                    } catch (Exception var18) {
                                                    }
                                                }

                                                return -1;
                                            default:
                                                return -1;
                                        }

                                        if (!this.inHandshake && null != this.retransmit) {
                                            this.retransmit = null;
                                            this.retransmitEpoch = null;
                                            this.retransmitTimeout = null;
                                        }

                                        System.arraycopy(decoded.buf, decoded.off, buf, off, decoded.len);
                                        return decoded.len;
                                    }
                                }
                            }
                        }
                    default:
                        return -1;
                }
            }
        }
    }

    private int receiveRecord(byte[] buf, int off, int len, int waitMillis) throws IOException {
        int received;
        int fragmentLength;
        if (this.recordQueue.available() > 0) {
            received = 0;
            if (this.recordQueue.available() >= 13) {
                byte[] lengthBytes = new byte[2];
                this.recordQueue.read(lengthBytes, 0, 2, 11);
                received = TlsUtils.readUint16(lengthBytes, 0);
            }

            fragmentLength = Math.min(this.recordQueue.available(), 13 + received);
            this.recordQueue.removeData(buf, off, fragmentLength, 0);
            return fragmentLength;
        } else {
            received = this.receiveDatagram(buf, off, len, waitMillis);
            if (received >= 13) {
                this.inConnection = true;
                fragmentLength = TlsUtils.readUint16(buf, off + 11);
                int recordLength = 13 + fragmentLength;
                if (received > recordLength) {
                    this.recordQueue.addData(buf, off + recordLength, received - recordLength);
                    received = recordLength;
                }
            }

            return received;
        }
    }

    private void resetHeartbeat() {
        this.heartbeatInFlight = null;
        this.heartbeatResendMillis = -1;
        this.heartbeatResendTimeout = null;
        this.heartbeatTimeout = new Timeout((long)this.heartbeat.getIdleMillis());
    }

    private void sendHeartbeatMessage(HeartbeatMessage heartbeatMessage) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        heartbeatMessage.encode(output);
        byte[] buf = output.toByteArray();
        this.sendRecord((short)24, buf, 0, buf.length);
    }

    private void sendRecord(short contentType, byte[] buf, int off, int len) throws IOException {
        if (this.writeVersion != null) {
            if (len > this.plaintextLimit) {
                throw new TlsFatalAlert((short)80);
            } else if (len < 1 && contentType != 23) {
                throw new TlsFatalAlert((short)80);
            } else {
                synchronized(this.writeLock) {
                    int recordEpoch = this.writeEpoch.getEpoch();
                    long recordSequenceNumber = this.writeEpoch.allocateSequenceNumber();
                    long macSequenceNumber = getMacSequenceNumber(recordEpoch, recordSequenceNumber);
                    ProtocolVersion recordVersion = this.writeVersion;
                    TlsEncodeResult encoded = this.writeEpoch.getCipher().encodePlaintext(macSequenceNumber, contentType, recordVersion, 13, buf, off, len);
                    int ciphertextLength = encoded.len - 13;
                    TlsUtils.checkUint16(ciphertextLength);
                    TlsUtils.writeUint8(encoded.recordType, encoded.buf, encoded.off + 0);
                    TlsUtils.writeVersion(recordVersion, encoded.buf, encoded.off + 1);
                    TlsUtils.writeUint16(recordEpoch, encoded.buf, encoded.off + 3);
                    TlsUtils.writeUint48(recordSequenceNumber, encoded.buf, encoded.off + 5);
                    TlsUtils.writeUint16(ciphertextLength, encoded.buf, encoded.off + 11);
                    sendDatagram(this.transport, encoded.buf, encoded.off, encoded.len);
                }
            }
        }
    }

    private static long getMacSequenceNumber(int epoch, long sequence_number) {
        return ((long)epoch & 4294967295L) << 48 | sequence_number;
    }
}