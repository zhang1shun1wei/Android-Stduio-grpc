package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Integers;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

/* access modifiers changed from: package-private */
public class DTLSReliableHandshake {
    static final int INITIAL_RESEND_MILLIS = 1000;
    private static final int MAX_RECEIVE_AHEAD = 16;
    private static final int MAX_RESEND_MILLIS = 60000;
    private static final int MESSAGE_HEADER_LENGTH = 12;
    private Hashtable currentInboundFlight = new Hashtable();
    private TlsHandshakeHash handshakeHash;
    private Timeout handshakeTimeout;
    private int next_receive_seq = 0;
    private int next_send_seq = 0;
    private Vector outboundFlight = new Vector();
    private Hashtable previousInboundFlight = null;
    private DTLSRecordLayer recordLayer;
    private int resendMillis = -1;
    private Timeout resendTimeout = null;

    static DTLSRequest readClientRequest(byte[] data, int dataOff, int dataLen, OutputStream dtlsOutput) throws IOException {
        byte[] message = DTLSRecordLayer.receiveClientHelloRecord(data, dataOff, dataLen);
        if (message == null || message.length < 12) {
            return null;
        }
        long recordSeq = TlsUtils.readUint48(data, dataOff + 5);
        if (1 != TlsUtils.readUint8(message, 0)) {
            return null;
        }
        int length = TlsUtils.readUint24(message, 1);
        if (message.length == length + 12 && TlsUtils.readUint24(message, 6) == 0 && length == TlsUtils.readUint24(message, 9)) {
            return new DTLSRequest(recordSeq, message, ClientHello.parse(new ByteArrayInputStream(message, 12, length), dtlsOutput));
        }
        return null;
    }

    static void sendHelloVerifyRequest(DatagramSender sender, long recordSeq, byte[] cookie) throws IOException {
        TlsUtils.checkUint8(cookie.length);
        int length = cookie.length + 3;
        byte[] message = new byte[(length + 12)];
        TlsUtils.writeUint8((short) 3, message, 0);
        TlsUtils.writeUint24(length, message, 1);
        TlsUtils.writeUint24(length, message, 9);
        TlsUtils.writeVersion(ProtocolVersion.DTLSv10, message, 12);
        TlsUtils.writeOpaque8(cookie, message, 14);
        DTLSRecordLayer.sendHelloVerifyRequestRecord(sender, recordSeq, message);
    }

    DTLSReliableHandshake(TlsContext context, DTLSRecordLayer transport, int timeoutMillis, DTLSRequest request) {
        this.recordLayer = transport;
        this.handshakeHash = new DeferredHash(context);
        this.handshakeTimeout = Timeout.forWaitMillis(timeoutMillis);
        if (request != null) {
            this.resendMillis = INITIAL_RESEND_MILLIS;
            this.resendTimeout = new Timeout((long) this.resendMillis);
            long recordSeq = request.getRecordSeq();
            int messageSeq = request.getMessageSeq();
            byte[] message = request.getMessage();
            this.recordLayer.resetAfterHelloVerifyRequestServer(recordSeq);
            this.currentInboundFlight.put(Integers.valueOf(messageSeq), new DTLSReassembler((short) 1, message.length - 12));
            this.next_send_seq = 1;
            this.next_receive_seq = messageSeq + 1;
            this.handshakeHash.update(message, 0, message.length);
        }
    }

    /* access modifiers changed from: package-private */
    public void resetAfterHelloVerifyRequestClient() {
        this.currentInboundFlight = new Hashtable();
        this.previousInboundFlight = null;
        this.outboundFlight = new Vector();
        this.resendMillis = -1;
        this.resendTimeout = null;
        this.next_receive_seq = 1;
        this.handshakeHash.reset();
    }

    /* access modifiers changed from: package-private */
    public TlsHandshakeHash getHandshakeHash() {
        return this.handshakeHash;
    }

    /* access modifiers changed from: package-private */
    public void prepareToFinish() {
        this.handshakeHash.stopTracking();
    }

    /* access modifiers changed from: package-private */
    public void sendMessage(short msg_type, byte[] body) throws IOException {
        TlsUtils.checkUint24(body.length);
        if (this.resendTimeout != null) {
            checkInboundFlight();
            this.resendMillis = -1;
            this.resendTimeout = null;
            this.outboundFlight.removeAllElements();
        }
        int i = this.next_send_seq;
        this.next_send_seq = i + 1;
        Message message = new Message(i, msg_type, body);
        this.outboundFlight.addElement(message);
        writeMessage(message);
        updateHandshakeMessagesDigest(message);
    }

    /* access modifiers changed from: package-private */
    public Message receiveMessage() throws IOException {
        Message message = implReceiveMessage();
        updateHandshakeMessagesDigest(message);
        return message;
    }

    /* access modifiers changed from: package-private */
    public byte[] receiveMessageBody(short msg_type) throws IOException {
        Message message = implReceiveMessage();
        if (message.getType() != msg_type) {
            throw new TlsFatalAlert((short) 10);
        }
        updateHandshakeMessagesDigest(message);
        return message.getBody();
    }

    /* access modifiers changed from: package-private */
    public Message receiveMessageDelayedDigest(short msg_type) throws IOException {
        Message message = implReceiveMessage();
        if (message.getType() == msg_type) {
            return message;
        }
        throw new TlsFatalAlert((short) 10);
    }

    /* access modifiers changed from: package-private */
    public void updateHandshakeMessagesDigest(Message message) throws IOException {
        short msg_type = message.getType();
        switch (msg_type) {
            case 0:
            case 3:
            case 24:
                return;
            default:
                byte[] body = message.getBody();
                byte[] buf = new byte[12];
                TlsUtils.writeUint8(msg_type, buf, 0);
                TlsUtils.writeUint24(body.length, buf, 1);
                TlsUtils.writeUint16(message.getSeq(), buf, 4);
                TlsUtils.writeUint24(0, buf, 6);
                TlsUtils.writeUint24(body.length, buf, 9);
                this.handshakeHash.update(buf, 0, buf.length);
                this.handshakeHash.update(body, 0, body.length);
                return;
        }
    }

    /* access modifiers changed from: package-private */
    public void finish() {
        DTLSHandshakeRetransmit retransmit = null;
        if (this.resendTimeout != null) {
            checkInboundFlight();
        } else {
            prepareInboundFlight(null);
            if (this.previousInboundFlight != null) {
                retransmit = new DTLSHandshakeRetransmit() {
                    /* class com.mi.car.jsse.easysec.tls.DTLSReliableHandshake.AnonymousClass1 */

                    @Override // com.mi.car.jsse.easysec.tls.DTLSHandshakeRetransmit
                    public void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len) throws IOException {
                        DTLSReliableHandshake.this.processRecord(0, epoch, buf, off, len);
                    }
                };
            }
        }
        this.recordLayer.handshakeSuccessful(retransmit);
    }

    static int backOff(int timeoutMillis) {
        return Math.min(timeoutMillis * 2, (int) MAX_RESEND_MILLIS);
    }

    /* JADX WARNING: Removed duplicated region for block: B:3:0x000c  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private void checkInboundFlight() {
        /*
            r4 = this;
            java.util.Hashtable r2 = r4.currentInboundFlight
            java.util.Enumeration r0 = r2.keys()
        L_0x0006:
            boolean r2 = r0.hasMoreElements()
            if (r2 == 0) goto L_0x001b
            java.lang.Object r1 = r0.nextElement()
            java.lang.Integer r1 = (java.lang.Integer) r1
            int r2 = r1.intValue()
            int r3 = r4.next_receive_seq
            if (r2 < r3) goto L_0x0006
            goto L_0x0006
        L_0x001b:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.tls.DTLSReliableHandshake.checkInboundFlight():void");
    }

    private Message getPendingMessage() throws IOException {
        byte[] body;
        DTLSReassembler next = (DTLSReassembler) this.currentInboundFlight.get(Integers.valueOf(this.next_receive_seq));
        if (next == null || (body = next.getBodyIfComplete()) == null) {
            return null;
        }
        this.previousInboundFlight = null;
        int i = this.next_receive_seq;
        this.next_receive_seq = i + 1;
        return new Message(i, next.getMsgType(), body);
    }

    private Message implReceiveMessage() throws IOException {
        long currentTimeMillis = System.currentTimeMillis();
        if (this.resendTimeout == null) {
            this.resendMillis = INITIAL_RESEND_MILLIS;
            this.resendTimeout = new Timeout((long) this.resendMillis, currentTimeMillis);
            prepareInboundFlight(new Hashtable());
        }
        byte[] buf = null;
        while (!this.recordLayer.isClosed()) {
            Message pending = getPendingMessage();
            if (pending != null) {
                return pending;
            }
            if (Timeout.hasExpired(this.handshakeTimeout, currentTimeMillis)) {
                throw new TlsTimeoutException("Handshake timed out");
            }
            int waitMillis = Timeout.constrainWaitMillis(Timeout.getWaitMillis(this.handshakeTimeout, currentTimeMillis), this.resendTimeout, currentTimeMillis);
            if (waitMillis < 1) {
                waitMillis = 1;
            }
            int receiveLimit = this.recordLayer.getReceiveLimit();
            if (buf == null || buf.length < receiveLimit) {
                buf = new byte[receiveLimit];
            }
            int received = this.recordLayer.receive(buf, 0, receiveLimit, waitMillis);
            if (received < 0) {
                resendOutboundFlight();
            } else {
                processRecord(16, this.recordLayer.getReadEpoch(), buf, 0, received);
            }
            currentTimeMillis = System.currentTimeMillis();
        }
        throw new TlsFatalAlert((short) 90);
    }

    private void prepareInboundFlight(Hashtable nextFlight) {
        resetAll(this.currentInboundFlight);
        this.previousInboundFlight = this.currentInboundFlight;
        this.currentInboundFlight = nextFlight;
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private void processRecord(int windowSize, int epoch, byte[] buf, int off, int len) throws IOException {
        int fragment_length;
        int message_length;
        DTLSReassembler reassembler;
        boolean checkPreviousFlight = false;
        while (len >= 12 && len >= (message_length = (fragment_length = TlsUtils.readUint24(buf, off + 9)) + 12)) {
            int length = TlsUtils.readUint24(buf, off + 1);
            int fragment_offset = TlsUtils.readUint24(buf, off + 6);
            if (fragment_offset + fragment_length <= length) {
                short msg_type = TlsUtils.readUint8(buf, off + 0);
                if (epoch != (msg_type == 20 ? 1 : 0)) {
                    break;
                }
                int message_seq = TlsUtils.readUint16(buf, off + 4);
                if (message_seq < this.next_receive_seq + windowSize) {
                    if (message_seq >= this.next_receive_seq) {
                        DTLSReassembler reassembler2 = (DTLSReassembler) this.currentInboundFlight.get(Integers.valueOf(message_seq));
                        if (reassembler2 == null) {
                            reassembler2 = new DTLSReassembler(msg_type, length);
                            this.currentInboundFlight.put(Integers.valueOf(message_seq), reassembler2);
                        }
                        reassembler2.contributeFragment(msg_type, length, buf, off + 12, fragment_offset, fragment_length);
                    } else if (!(this.previousInboundFlight == null || (reassembler = (DTLSReassembler) this.previousInboundFlight.get(Integers.valueOf(message_seq))) == null)) {
                        reassembler.contributeFragment(msg_type, length, buf, off + 12, fragment_offset, fragment_length);
                        checkPreviousFlight = true;
                    }
                }
                off += message_length;
                len -= message_length;
            } else {
                break;
            }
        }
        if (checkPreviousFlight && checkAll(this.previousInboundFlight)) {
            resendOutboundFlight();
            resetAll(this.previousInboundFlight);
        }
    }

    private void resendOutboundFlight() throws IOException {
        this.recordLayer.resetWriteEpoch();
        for (int i = 0; i < this.outboundFlight.size(); i++) {
            writeMessage((Message) this.outboundFlight.elementAt(i));
        }
        this.resendMillis = backOff(this.resendMillis);
        this.resendTimeout = new Timeout((long) this.resendMillis);
    }

    private void writeMessage(Message message) throws IOException {
        int fragmentLimit = this.recordLayer.getSendLimit() - 12;
        if (fragmentLimit < 1) {
            throw new TlsFatalAlert((short) 80);
        }
        int length = message.getBody().length;
        int fragment_offset = 0;
        do {
            int fragment_length = Math.min(length - fragment_offset, fragmentLimit);
            writeHandshakeFragment(message, fragment_offset, fragment_length);
            fragment_offset += fragment_length;
        } while (fragment_offset < length);
    }

    private void writeHandshakeFragment(Message message, int fragment_offset, int fragment_length) throws IOException {
        RecordLayerBuffer fragment = new RecordLayerBuffer(fragment_length + 12);
        TlsUtils.writeUint8(message.getType(), (OutputStream) fragment);
        TlsUtils.writeUint24(message.getBody().length, fragment);
        TlsUtils.writeUint16(message.getSeq(), fragment);
        TlsUtils.writeUint24(fragment_offset, fragment);
        TlsUtils.writeUint24(fragment_length, fragment);
        fragment.write(message.getBody(), fragment_offset, fragment_length);
        fragment.sendToRecordLayer(this.recordLayer);
    }

    private static boolean checkAll(Hashtable inboundFlight) {
        Enumeration e = inboundFlight.elements();
        while (e.hasMoreElements()) {
            if (((DTLSReassembler) e.nextElement()).getBodyIfComplete() == null) {
                return false;
            }
        }
        return true;
    }

    private static void resetAll(Hashtable inboundFlight) {
        Enumeration e = inboundFlight.elements();
        while (e.hasMoreElements()) {
            ((DTLSReassembler) e.nextElement()).reset();
        }
    }

    /* access modifiers changed from: package-private */
    public static class Message {
        private final byte[] body;
        private final int message_seq;
        private final short msg_type;

        private Message(int message_seq2, short msg_type2, byte[] body2) {
            this.message_seq = message_seq2;
            this.msg_type = msg_type2;
            this.body = body2;
        }

        public int getSeq() {
            return this.message_seq;
        }

        public short getType() {
            return this.msg_type;
        }

        public byte[] getBody() {
            return this.body;
        }
    }

    /* access modifiers changed from: package-private */
    public static class RecordLayerBuffer extends ByteArrayOutputStream {
        RecordLayerBuffer(int size) {
            super(size);
        }

        /* access modifiers changed from: package-private */
        public void sendToRecordLayer(DTLSRecordLayer recordLayer) throws IOException {
            recordLayer.send(this.buf, 0, this.count);
            this.buf = null;
        }
    }
}
