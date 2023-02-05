//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.SessionParameters.Builder;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

public abstract class TlsProtocol implements TlsCloseable {
    protected static final Integer EXT_RenegotiationInfo = Integers.valueOf(65281);
    protected static final Integer EXT_SessionTicket = Integers.valueOf(35);
    protected static final short CS_START = 0;
    protected static final short CS_CLIENT_HELLO = 1;
    protected static final short CS_SERVER_HELLO_RETRY_REQUEST = 2;
    protected static final short CS_CLIENT_HELLO_RETRY = 3;
    protected static final short CS_SERVER_HELLO = 4;
    protected static final short CS_SERVER_ENCRYPTED_EXTENSIONS = 5;
    protected static final short CS_SERVER_SUPPLEMENTAL_DATA = 6;
    protected static final short CS_SERVER_CERTIFICATE = 7;
    protected static final short CS_SERVER_CERTIFICATE_STATUS = 8;
    protected static final short CS_SERVER_CERTIFICATE_VERIFY = 9;
    protected static final short CS_SERVER_KEY_EXCHANGE = 10;
    protected static final short CS_SERVER_CERTIFICATE_REQUEST = 11;
    protected static final short CS_SERVER_HELLO_DONE = 12;
    protected static final short CS_CLIENT_END_OF_EARLY_DATA = 13;
    protected static final short CS_CLIENT_SUPPLEMENTAL_DATA = 14;
    protected static final short CS_CLIENT_CERTIFICATE = 15;
    protected static final short CS_CLIENT_KEY_EXCHANGE = 16;
    protected static final short CS_CLIENT_CERTIFICATE_VERIFY = 17;
    protected static final short CS_CLIENT_FINISHED = 18;
    protected static final short CS_SERVER_SESSION_TICKET = 19;
    protected static final short CS_SERVER_FINISHED = 20;
    protected static final short CS_END = 21;
    protected static final short ADS_MODE_1_Nsub1 = 0;
    protected static final short ADS_MODE_0_N = 1;
    protected static final short ADS_MODE_0_N_FIRSTONLY = 2;
    private ByteQueue applicationDataQueue = new ByteQueue(0);
    private ByteQueue alertQueue = new ByteQueue(2);
    private ByteQueue handshakeQueue = new ByteQueue(0);
    final RecordStream recordStream;
    final Object recordWriteLock = new Object();
    private int maxHandshakeMessageSize = -1;
    TlsHandshakeHash handshakeHash;
    private TlsInputStream tlsInputStream = null;
    private TlsOutputStream tlsOutputStream = null;
    private volatile boolean closed = false;
    private volatile boolean failedWithError = false;
    private volatile boolean appDataReady = false;
    private volatile boolean appDataSplitEnabled = true;
    private volatile boolean keyUpdateEnabled = false;
    private volatile boolean keyUpdatePendingSend = false;
    private volatile boolean resumableHandshake = false;
    private volatile int appDataSplitMode = 0;
    protected TlsSession tlsSession = null;
    protected SessionParameters sessionParameters = null;
    protected TlsSecret sessionMasterSecret = null;
    protected byte[] retryCookie = null;
    protected int retryGroup = -1;
    protected Hashtable clientExtensions = null;
    protected Hashtable serverExtensions = null;
    protected short connection_state = 0;
    protected boolean resumedSession = false;
    protected boolean selectedPSK13 = false;
    protected boolean receivedChangeCipherSpec = false;
    protected boolean expectSessionTicket = false;
    protected boolean blocking;
    protected ByteQueueInputStream inputBuffers;
    protected ByteQueueOutputStream outputBuffer;

    protected boolean isLegacyConnectionState() {
        switch(this.connection_state) {
            case 0:
            case 1:
            case 4:
            case 6:
            case 7:
            case 8:
            case 10:
            case 11:
            case 12:
            case 14:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
                return true;
            case 2:
            case 3:
            case 5:
            case 9:
            case 13:
            default:
                return false;
        }
    }

    protected boolean isTLSv13ConnectionState() {
        switch(this.connection_state) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 7:
            case 9:
            case 11:
            case 13:
            case 15:
            case 17:
            case 18:
            case 20:
            case 21:
                return true;
            case 6:
            case 8:
            case 10:
            case 12:
            case 14:
            case 16:
            case 19:
            default:
                return false;
        }
    }

    protected TlsProtocol() {
        this.blocking = false;
        this.inputBuffers = new ByteQueueInputStream();
        this.outputBuffer = new ByteQueueOutputStream();
        this.recordStream = new RecordStream(this, this.inputBuffers, this.outputBuffer);
    }

    protected TlsProtocol(InputStream input, OutputStream output) {
        this.blocking = true;
        this.recordStream = new RecordStream(this, input, output);
    }

    public void resumeHandshake() throws IOException {
        if (!this.blocking) {
            throw new IllegalStateException("Cannot use resumeHandshake() in non-blocking mode!");
        } else if (!this.isHandshaking()) {
            throw new IllegalStateException("No handshake in progress");
        } else {
            this.blockForHandshake();
        }
    }

    protected void closeConnection() throws IOException {
        this.recordStream.close();
    }

    protected abstract TlsContext getContext();

    abstract AbstractTlsContext getContextAdmin();

    protected abstract TlsPeer getPeer();

    protected int getRenegotiationPolicy() {
        return 0;
    }

    protected void handleAlertMessage(short alertLevel, short alertDescription) throws IOException {
        this.getPeer().notifyAlertReceived(alertLevel, alertDescription);
        if (alertLevel == 1) {
            this.handleAlertWarningMessage(alertDescription);
        } else {
            this.handleFailure();
            throw new TlsFatalAlertReceived(alertDescription);
        }
    }

    protected void handleAlertWarningMessage(short alertDescription) throws IOException {
        switch(alertDescription) {
            case 0:
                if (!this.appDataReady) {
                    throw new TlsFatalAlert((short)40);
                } else {
                    this.handleClose(false);
                }
            default:
                return;
            case 41:
                throw new TlsFatalAlert((short)10);
            case 100:
                throw new TlsFatalAlert((short)40);
        }
    }

    protected void handleChangeCipherSpecMessage() throws IOException {
    }

    protected void handleClose(boolean user_canceled) throws IOException {
        if (!this.closed) {
            this.closed = true;
            if (!this.appDataReady) {
                this.cleanupHandshake();
                if (user_canceled) {
                    this.raiseAlertWarning((short)90, "User canceled handshake");
                }
            }

            this.raiseAlertWarning((short)0, "Connection closed");
            this.closeConnection();
        }

    }

    protected void handleException(short alertDescription, String message, Throwable e) throws IOException {
        if (!this.appDataReady && !this.isResumableHandshake() || !(e instanceof InterruptedIOException)) {
            if (!this.closed) {
                this.raiseAlertFatal(alertDescription, message, e);
                this.handleFailure();
            }

        }
    }

    protected void handleFailure() throws IOException {
        this.closed = true;
        this.failedWithError = true;
        this.invalidateSession();
        if (!this.appDataReady) {
            this.cleanupHandshake();
        }

        this.closeConnection();
    }

    protected abstract void handleHandshakeMessage(short var1, HandshakeMessageInput var2) throws IOException;

    protected boolean handleRenegotiation() throws IOException {
        int renegotiationPolicy = 0;
        SecurityParameters securityParameters = this.getContext().getSecurityParametersConnection();
        if (null != securityParameters && securityParameters.isSecureRenegotiation()) {
            Certificate serverCertificate = 0 == securityParameters.getEntity() ? securityParameters.getLocalCertificate() : securityParameters.getPeerCertificate();
            if (null != serverCertificate && !serverCertificate.isEmpty()) {
                renegotiationPolicy = this.getRenegotiationPolicy();
            }
        }

        switch(renegotiationPolicy) {
            case 0:
            default:
                this.refuseRenegotiation();
                return false;
            case 1:
                return false;
            case 2:
                this.beginHandshake(true);
                return true;
        }
    }

    protected void applyMaxFragmentLengthExtension(short maxFragmentLength) throws IOException {
        if (maxFragmentLength >= 0) {
            if (!MaxFragmentLength.isValid(maxFragmentLength)) {
                throw new TlsFatalAlert((short)80);
            }

            int plainTextLimit = 1 << 8 + maxFragmentLength;
            this.recordStream.setPlaintextLimit(plainTextLimit);
        }

    }

    protected void checkReceivedChangeCipherSpec(boolean expected) throws IOException {
        if (expected != this.receivedChangeCipherSpec) {
            throw new TlsFatalAlert((short)10);
        }
    }

    protected void blockForHandshake() throws IOException {
        while(this.connection_state != 21) {
            if (this.isClosed()) {
                throw new TlsFatalAlert((short)80);
            }

            this.safeReadRecord();
        }

    }

    protected void beginHandshake(boolean renegotiation) throws IOException {
        AbstractTlsContext context = this.getContextAdmin();
        TlsPeer peer = this.getPeer();
        this.maxHandshakeMessageSize = Math.max(1024, peer.getMaxHandshakeMessageSize());
        this.handshakeHash = new DeferredHash(context);
        this.connection_state = 0;
        this.resumedSession = false;
        this.selectedPSK13 = false;
        context.handshakeBeginning(peer);
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        if (renegotiation != securityParameters.isRenegotiating()) {
            throw new TlsFatalAlert((short)80);
        } else {
            securityParameters.extendedPadding = peer.shouldUseExtendedPadding();
        }
    }

    protected void cleanupHandshake() {
        TlsContext context = this.getContext();
        if (null != context) {
            SecurityParameters securityParameters = context.getSecurityParameters();
            if (null != securityParameters) {
                securityParameters.clear();
            }
        }

        this.tlsSession = null;
        this.sessionParameters = null;
        this.sessionMasterSecret = null;
        this.retryCookie = null;
        this.retryGroup = -1;
        this.clientExtensions = null;
        this.serverExtensions = null;
        this.resumedSession = false;
        this.selectedPSK13 = false;
        this.receivedChangeCipherSpec = false;
        this.expectSessionTicket = false;
    }

    protected void completeHandshake() throws IOException {
        try {
            AbstractTlsContext context = this.getContextAdmin();
            SecurityParameters securityParameters = context.getSecurityParametersHandshake();
            if (!context.isHandshaking() || null == securityParameters.getLocalVerifyData() || null == securityParameters.getPeerVerifyData()) {
                throw new TlsFatalAlert((short)80);
            }

            this.recordStream.finaliseHandshake();
            this.connection_state = 21;
            this.handshakeHash = new DeferredHash(context);
            this.alertQueue.shrink();
            this.handshakeQueue.shrink();
            ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
            this.appDataSplitEnabled = !TlsUtils.isTLSv11(negotiatedVersion);
            this.appDataReady = true;
            this.keyUpdateEnabled = TlsUtils.isTLSv13(negotiatedVersion);
            if (this.blocking) {
                this.tlsInputStream = new TlsInputStream(this);
                this.tlsOutputStream = new TlsOutputStream(this);
            }

            if (this.sessionParameters == null) {
                this.sessionMasterSecret = securityParameters.getMasterSecret();
                this.sessionParameters = (new Builder()).setCipherSuite(securityParameters.getCipherSuite()).setCompressionAlgorithm(securityParameters.getCompressionAlgorithm()).setExtendedMasterSecret(securityParameters.isExtendedMasterSecret()).setLocalCertificate(securityParameters.getLocalCertificate()).setMasterSecret(context.getCrypto().adoptSecret(this.sessionMasterSecret)).setNegotiatedVersion(securityParameters.getNegotiatedVersion()).setPeerCertificate(securityParameters.getPeerCertificate()).setPSKIdentity(securityParameters.getPSKIdentity()).setSRPIdentity(securityParameters.getSRPIdentity()).setServerExtensions(this.serverExtensions).build();
                this.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), this.sessionParameters);
            } else {
                securityParameters.localCertificate = this.sessionParameters.getLocalCertificate();
                securityParameters.peerCertificate = this.sessionParameters.getPeerCertificate();
                securityParameters.pskIdentity = this.sessionParameters.getPSKIdentity();
                securityParameters.srpIdentity = this.sessionParameters.getSRPIdentity();
            }

            context.handshakeComplete(this.getPeer(), this.tlsSession);
        } finally {
            this.cleanupHandshake();
        }

    }

    protected void processRecord(short protocol, byte[] buf, int off, int len) throws IOException {
        switch(protocol) {
            case 20:
                this.processChangeCipherSpec(buf, off, len);
                break;
            case 21:
                this.alertQueue.addData(buf, off, len);
                this.processAlertQueue();
                break;
            case 22:
                if (this.handshakeQueue.available() > 0) {
                    this.handshakeQueue.addData(buf, off, len);
                    this.processHandshakeQueue(this.handshakeQueue);
                } else {
                    ByteQueue tmpQueue = new ByteQueue(buf, off, len);
                    this.processHandshakeQueue(tmpQueue);
                    int remaining = tmpQueue.available();
                    if (remaining > 0) {
                        this.handshakeQueue.addData(buf, off + len - remaining, remaining);
                    }
                }
                break;
            case 23:
                if (!this.appDataReady) {
                    throw new TlsFatalAlert((short)10);
                }

                this.applicationDataQueue.addData(buf, off, len);
                this.processApplicationDataQueue();
                break;
            default:
                throw new TlsFatalAlert((short)10);
        }

    }

    private void processHandshakeQueue(ByteQueue queue) throws IOException {
        while(true) {
            if (queue.available() >= 4) {
                int header = queue.readInt32();
                short type = (short)(header >>> 24);
                if (!HandshakeType.isRecognized(type)) {
                    throw new TlsFatalAlert((short)10, "Handshake message of unrecognized type: " + type);
                }

                int length = header & 16777215;
                if (length > this.maxHandshakeMessageSize) {
                    throw new TlsFatalAlert((short)80, "Handshake message length exceeds the maximum: " + HandshakeType.getText(type) + ", " + length + " > " + this.maxHandshakeMessageSize);
                }

                int totalLength = 4 + length;
                if (queue.available() >= totalLength) {
                    switch(type) {
                        default:
                            ProtocolVersion negotiatedVersion = this.getContext().getServerVersion();
                            if (null == negotiatedVersion || !TlsUtils.isTLSv13(negotiatedVersion)) {
                                this.checkReceivedChangeCipherSpec(20 == type);
                            }
                        case 0:
                            HandshakeMessageInput buf = queue.readHandshakeMessage(totalLength);
                            switch(type) {
                                case 0:
                                case 1:
                                case 2:
                                case 15:
                                case 20:
                                case 24:
                                    break;
                                case 3:
                                case 5:
                                case 6:
                                case 7:
                                case 8:
                                case 9:
                                case 10:
                                case 11:
                                case 12:
                                case 13:
                                case 14:
                                case 16:
                                case 17:
                                case 18:
                                case 19:
                                case 21:
                                case 22:
                                case 23:
                                default:
                                    buf.updateHash(this.handshakeHash);
                                    break;
                                case 4:
                                    negotiatedVersion = this.getContext().getServerVersion();
                                    if (null != negotiatedVersion && !TlsUtils.isTLSv13(negotiatedVersion)) {
                                        buf.updateHash(this.handshakeHash);
                                    }
                            }

                            buf.skip(4L);
                            this.handleHandshakeMessage(type, buf);
                            continue;
                    }
                }
            }

            return;
        }
    }

    private void processApplicationDataQueue() {
    }

    private void processAlertQueue() throws IOException {
        while(this.alertQueue.available() >= 2) {
            byte[] alert = this.alertQueue.removeData(2, 0);
            short alertLevel = (short)alert[0];
            short alertDescription = (short)alert[1];
            this.handleAlertMessage(alertLevel, alertDescription);
        }

    }

    private void processChangeCipherSpec(byte[] buf, int off, int len) throws IOException {
        ProtocolVersion negotiatedVersion = this.getContext().getServerVersion();
        if (null != negotiatedVersion && !TlsUtils.isTLSv13(negotiatedVersion)) {
            for(int i = 0; i < len; ++i) {
                short message = TlsUtils.readUint8(buf, off + i);
                if (message != 1) {
                    throw new TlsFatalAlert((short)50);
                }

                if (this.receivedChangeCipherSpec || this.alertQueue.available() > 0 || this.handshakeQueue.available() > 0) {
                    throw new TlsFatalAlert((short)10);
                }

                this.recordStream.notifyChangeCipherSpecReceived();
                this.receivedChangeCipherSpec = true;
                this.handleChangeCipherSpecMessage();
            }

        } else {
            throw new TlsFatalAlert((short)10);
        }
    }

    public int applicationDataAvailable() {
        return this.applicationDataQueue.available();
    }

    public int readApplicationData(byte[] buf, int offset, int len) throws IOException {
        if (len < 1) {
            return 0;
        } else {
            while(this.applicationDataQueue.available() == 0) {
                if (this.closed) {
                    if (this.failedWithError) {
                        throw new IOException("Cannot read application data on failed TLS connection");
                    }

                    return -1;
                }

                if (!this.appDataReady) {
                    throw new IllegalStateException("Cannot read application data until initial handshake completed.");
                }

                this.safeReadRecord();
            }

            len = Math.min(len, this.applicationDataQueue.available());
            this.applicationDataQueue.removeData(buf, offset, len, 0);
            return len;
        }
    }

    protected RecordPreview safePreviewRecordHeader(byte[] recordHeader) throws IOException {
        try {
            return this.recordStream.previewRecordHeader(recordHeader);
        } catch (TlsFatalAlert var3) {
            this.handleException(var3.getAlertDescription(), "Failed to read record", var3);
            throw var3;
        } catch (IOException var4) {
            this.handleException((short)80, "Failed to read record", var4);
            throw var4;
        } catch (RuntimeException var5) {
            this.handleException((short)80, "Failed to read record", var5);
            throw new TlsFatalAlert((short)80, var5);
        }
    }

    protected void safeReadRecord() throws IOException {
        try {
            if (this.recordStream.readRecord()) {
                return;
            }

            if (!this.appDataReady) {
                throw new TlsFatalAlert((short)40);
            }

            if (!this.getPeer().requiresCloseNotify()) {
                this.handleClose(false);
                return;
            }
        } catch (TlsFatalAlertReceived var2) {
            throw var2;
        } catch (TlsFatalAlert var3) {
            this.handleException(var3.getAlertDescription(), "Failed to read record", var3);
            throw var3;
        } catch (IOException var4) {
            this.handleException((short)80, "Failed to read record", var4);
            throw var4;
        } catch (RuntimeException var5) {
            this.handleException((short)80, "Failed to read record", var5);
            throw new TlsFatalAlert((short)80, var5);
        }

        this.handleFailure();
        throw new TlsNoCloseNotifyException();
    }

    protected boolean safeReadFullRecord(byte[] input, int inputOff, int inputLen) throws IOException {
        try {
            return this.recordStream.readFullRecord(input, inputOff, inputLen);
        } catch (TlsFatalAlert var5) {
            this.handleException(var5.getAlertDescription(), "Failed to process record", var5);
            throw var5;
        } catch (IOException var6) {
            this.handleException((short)80, "Failed to process record", var6);
            throw var6;
        } catch (RuntimeException var7) {
            this.handleException((short)80, "Failed to process record", var7);
            throw new TlsFatalAlert((short)80, var7);
        }
    }

    protected void safeWriteRecord(short type, byte[] buf, int offset, int len) throws IOException {
        try {
            this.recordStream.writeRecord(type, buf, offset, len);
        } catch (TlsFatalAlert var6) {
            this.handleException(var6.getAlertDescription(), "Failed to write record", var6);
            throw var6;
        } catch (IOException var7) {
            this.handleException((short)80, "Failed to write record", var7);
            throw var7;
        } catch (RuntimeException var8) {
            this.handleException((short)80, "Failed to write record", var8);
            throw new TlsFatalAlert((short)80, var8);
        }
    }

    public void writeApplicationData(byte[] buf, int offset, int len) throws IOException {
        if (!this.appDataReady) {
            throw new IllegalStateException("Cannot write application data until initial handshake completed.");
        } else {
            synchronized(this.recordWriteLock) {
                while(len > 0) {
                    if (this.closed) {
                        throw new IOException("Cannot write application data on closed/failed TLS connection");
                    }

                    if (this.appDataSplitEnabled) {
                        switch(this.appDataSplitMode) {
                            case 0:
                            default:
                                if (len > 1) {
                                    this.safeWriteRecord((short)23, buf, offset, 1);
                                    ++offset;
                                    --len;
                                }
                                break;
                            case 2:
                                this.appDataSplitEnabled = false;
                            case 1:
                                this.safeWriteRecord((short)23, TlsUtils.EMPTY_BYTES, 0, 0);
                        }
                    } else if (this.keyUpdateEnabled) {
                        if (this.keyUpdatePendingSend) {
                            this.send13KeyUpdate(false);
                        } else if (this.recordStream.needsKeyUpdate()) {
                            this.send13KeyUpdate(true);
                        }
                    }

                    int toWrite = Math.min(len, this.recordStream.getPlaintextLimit());
                    this.safeWriteRecord((short)23, buf, offset, toWrite);
                    offset += toWrite;
                    len -= toWrite;
                }

            }
        }
    }

    public int getAppDataSplitMode() {
        return this.appDataSplitMode;
    }

    public void setAppDataSplitMode(int appDataSplitMode) {
        if (appDataSplitMode >= 0 && appDataSplitMode <= 2) {
            this.appDataSplitMode = appDataSplitMode;
        } else {
            throw new IllegalArgumentException("Illegal appDataSplitMode mode: " + appDataSplitMode);
        }
    }

    public boolean isResumableHandshake() {
        return this.resumableHandshake;
    }

    public void setResumableHandshake(boolean resumableHandshake) {
        this.resumableHandshake = resumableHandshake;
    }

    void writeHandshakeMessage(byte[] buf, int off, int len) throws IOException {
        if (len < 4) {
            throw new TlsFatalAlert((short)80);
        } else {
            short type = TlsUtils.readUint8(buf, off);
            switch(type) {
                case 0:
                case 1:
                case 24:
                    break;
                case 4:
                    ProtocolVersion negotiatedVersion = this.getContext().getServerVersion();
                    if (null != negotiatedVersion && !TlsUtils.isTLSv13(negotiatedVersion)) {
                        this.handshakeHash.update(buf, off, len);
                    }
                    break;
                default:
                    this.handshakeHash.update(buf, off, len);
            }

            int total = 0;

            do {
                int toWrite = Math.min(len - total, this.recordStream.getPlaintextLimit());
                this.safeWriteRecord((short)22, buf, off + total, toWrite);
                total += toWrite;
            } while(total < len);

        }
    }

    public OutputStream getOutputStream() {
        if (!this.blocking) {
            throw new IllegalStateException("Cannot use OutputStream in non-blocking mode! Use offerOutput() instead.");
        } else {
            return this.tlsOutputStream;
        }
    }

    public InputStream getInputStream() {
        if (!this.blocking) {
            throw new IllegalStateException("Cannot use InputStream in non-blocking mode! Use offerInput() instead.");
        } else {
            return this.tlsInputStream;
        }
    }

    public void closeInput() throws IOException {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use closeInput() in blocking mode!");
        } else if (!this.closed) {
            if (this.inputBuffers.available() > 0) {
                throw new EOFException();
            } else if (!this.appDataReady) {
                throw new TlsFatalAlert((short)40);
            } else if (!this.getPeer().requiresCloseNotify()) {
                this.handleClose(false);
            } else {
                this.handleFailure();
                throw new TlsNoCloseNotifyException();
            }
        }
    }

    public RecordPreview previewInputRecord(byte[] recordHeader) throws IOException {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use previewInputRecord() in blocking mode!");
        } else if (this.inputBuffers.available() != 0) {
            throw new IllegalStateException("Can only use previewInputRecord() for record-aligned input.");
        } else if (this.closed) {
            throw new IOException("Connection is closed, cannot accept any more input");
        } else {
            return this.safePreviewRecordHeader(recordHeader);
        }
    }

    public RecordPreview previewOutputRecord(int applicationDataSize) throws IOException {
        if (!this.appDataReady) {
            throw new IllegalStateException("Cannot use previewOutputRecord() until initial handshake completed.");
        } else if (this.blocking) {
            throw new IllegalStateException("Cannot use previewOutputRecord() in blocking mode!");
        } else if (this.outputBuffer.getBuffer().available() != 0) {
            throw new IllegalStateException("Can only use previewOutputRecord() for record-aligned output.");
        } else if (this.closed) {
            throw new IOException("Connection is closed, cannot produce any more output");
        } else if (applicationDataSize < 1) {
            return new RecordPreview(0, 0);
        } else {
            RecordPreview a;
            if (this.appDataSplitEnabled) {
                RecordPreview b;
                switch(this.appDataSplitMode) {
                    case 0:
                    default:
                        a = this.recordStream.previewOutputRecord(1);
                        if (applicationDataSize > 1) {
                            b = this.recordStream.previewOutputRecord(applicationDataSize - 1);
                            a = RecordPreview.combineAppData(a, b);
                        }

                        return a;
                    case 1:
                    case 2:
                        a = this.recordStream.previewOutputRecord(0);
                        b = this.recordStream.previewOutputRecord(applicationDataSize);
                        return RecordPreview.combineAppData(a, b);
                }
            } else {
                a = this.recordStream.previewOutputRecord(applicationDataSize);
                if (this.keyUpdateEnabled && (this.keyUpdatePendingSend || this.recordStream.needsKeyUpdate())) {
                    int keyUpdateLength = HandshakeMessageOutput.getLength(1);
                    int recordSize = this.recordStream.previewOutputRecordSize(keyUpdateLength);
                    a = RecordPreview.extendRecordSize(a, recordSize);
                }

                return a;
            }
        }
    }

    public void offerInput(byte[] input) throws IOException {
        this.offerInput(input, 0, input.length);
    }

    public void offerInput(byte[] input, int inputOff, int inputLen) throws IOException {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use offerInput() in blocking mode! Use getInputStream() instead.");
        } else if (this.closed) {
            throw new IOException("Connection is closed, cannot accept any more input");
        } else if (this.inputBuffers.available() == 0 && this.safeReadFullRecord(input, inputOff, inputLen)) {
            if (this.closed && !this.appDataReady) {
                throw new TlsFatalAlert((short)80);
            }
        } else {
            this.inputBuffers.addBytes(input, inputOff, inputLen);

            while(this.inputBuffers.available() >= 5) {
                byte[] recordHeader = new byte[5];
                if (5 != this.inputBuffers.peek(recordHeader)) {
                    throw new TlsFatalAlert((short)80);
                }

                RecordPreview preview = this.safePreviewRecordHeader(recordHeader);
                if (this.inputBuffers.available() < preview.getRecordSize()) {
                    break;
                }

                this.safeReadRecord();
                if (this.closed) {
                    if (!this.appDataReady) {
                        throw new TlsFatalAlert((short)80);
                    }
                    break;
                }
            }

        }
    }

    public int getApplicationDataLimit() {
        return this.recordStream.getPlaintextLimit();
    }

    public int getAvailableInputBytes() {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use getAvailableInputBytes() in blocking mode! Use getInputStream().available() instead.");
        } else {
            return this.applicationDataAvailable();
        }
    }

    public int readInput(byte[] buffer, int offset, int length) {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use readInput() in blocking mode! Use getInputStream() instead.");
        } else {
            length = Math.min(length, this.applicationDataQueue.available());
            if (length < 1) {
                return 0;
            } else {
                this.applicationDataQueue.removeData(buffer, offset, length, 0);
                return length;
            }
        }
    }

    public int getAvailableOutputBytes() {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use getAvailableOutputBytes() in blocking mode! Use getOutputStream() instead.");
        } else {
            return this.outputBuffer.getBuffer().available();
        }
    }

    public int readOutput(byte[] buffer, int offset, int length) {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use readOutput() in blocking mode! Use getOutputStream() instead.");
        } else {
            int bytesToRead = Math.min(this.getAvailableOutputBytes(), length);
            this.outputBuffer.getBuffer().removeData(buffer, offset, bytesToRead, 0);
            return bytesToRead;
        }
    }

    protected boolean establishSession(TlsSession sessionToResume) {
        this.tlsSession = null;
        this.sessionParameters = null;
        this.sessionMasterSecret = null;
        if (null != sessionToResume && sessionToResume.isResumable()) {
            SessionParameters sessionParameters = sessionToResume.exportSessionParameters();
            if (null == sessionParameters) {
                return false;
            } else {
                if (!sessionParameters.isExtendedMasterSecret()) {
                    TlsPeer peer = this.getPeer();
                    if (!peer.allowLegacyResumption() || peer.requiresExtendedMasterSecret()) {
                        return false;
                    }
                }

                TlsSecret sessionMasterSecret = TlsUtils.getSessionMasterSecret(this.getContext().getCrypto(), sessionParameters.getMasterSecret());
                if (null == sessionMasterSecret) {
                    return false;
                } else {
                    this.tlsSession = sessionToResume;
                    this.sessionParameters = sessionParameters;
                    this.sessionMasterSecret = sessionMasterSecret;
                    return true;
                }
            }
        } else {
            return false;
        }
    }

    protected void invalidateSession() {
        if (this.sessionMasterSecret != null) {
            this.sessionMasterSecret.destroy();
            this.sessionMasterSecret = null;
        }

        if (this.sessionParameters != null) {
            this.sessionParameters.clear();
            this.sessionParameters = null;
        }

        if (this.tlsSession != null) {
            this.tlsSession.invalidate();
            this.tlsSession = null;
        }

    }

    protected void processFinishedMessage(ByteArrayInputStream buf) throws IOException {
        TlsContext context = this.getContext();
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        boolean isServerContext = context.isServer();
        byte[] verify_data = TlsUtils.readFully(securityParameters.getVerifyDataLength(), buf);
        assertEmpty(buf);
        byte[] expected_verify_data = TlsUtils.calculateVerifyData(context, this.handshakeHash, !isServerContext);
        if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data)) {
            throw new TlsFatalAlert((short)51);
        } else {
            securityParameters.peerVerifyData = expected_verify_data;
            if ((!this.resumedSession || securityParameters.isExtendedMasterSecret()) && null == securityParameters.getLocalVerifyData()) {
                securityParameters.tlsUnique = expected_verify_data;
            }

        }
    }

    protected void process13FinishedMessage(ByteArrayInputStream buf) throws IOException {
        TlsContext context = this.getContext();
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        boolean isServerContext = context.isServer();
        byte[] verify_data = TlsUtils.readFully(securityParameters.getVerifyDataLength(), buf);
        assertEmpty(buf);
        byte[] expected_verify_data = TlsUtils.calculateVerifyData(context, this.handshakeHash, !isServerContext);
        if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data)) {
            throw new TlsFatalAlert((short)51);
        } else {
            securityParameters.peerVerifyData = expected_verify_data;
            securityParameters.tlsUnique = null;
        }
    }

    protected void raiseAlertFatal(short alertDescription, String message, Throwable cause) throws IOException {
        this.getPeer().notifyAlertRaised((short)2, alertDescription, message, cause);
        byte[] alert = new byte[]{2, (byte)alertDescription};

        try {
            this.recordStream.writeRecord((short)21, alert, 0, 2);
        } catch (Exception var6) {
        }

    }

    protected void raiseAlertWarning(short alertDescription, String message) throws IOException {
        this.getPeer().notifyAlertRaised((short)1, alertDescription, message, (Throwable)null);
        byte[] alert = new byte[]{1, (byte)alertDescription};
        this.safeWriteRecord((short)21, alert, 0, 2);
    }

    protected void receive13KeyUpdate(ByteArrayInputStream buf) throws IOException {
        if (this.appDataReady && this.keyUpdateEnabled) {
            short requestUpdate = TlsUtils.readUint8(buf);
            assertEmpty(buf);
            if (!KeyUpdateRequest.isValid(requestUpdate)) {
                throw new TlsFatalAlert((short)47);
            } else {
                boolean updateRequested = 1 == requestUpdate;
                TlsUtils.update13TrafficSecretPeer(this.getContext());
                this.recordStream.notifyKeyUpdateReceived();
                this.keyUpdatePendingSend |= updateRequested;
            }
        } else {
            throw new TlsFatalAlert((short)10);
        }
    }

    protected void sendCertificateMessage(Certificate certificate, OutputStream endPointHash) throws IOException {
        TlsContext context = this.getContext();
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        if (null != securityParameters.getLocalCertificate()) {
            throw new TlsFatalAlert((short)80);
        } else {
            if (null == certificate) {
                certificate = Certificate.EMPTY_CHAIN;
            }

            if (certificate.isEmpty() && !context.isServer() && securityParameters.getNegotiatedVersion().isSSL()) {
                String message = "SSLv3 client didn't provide credentials";
                this.raiseAlertWarning((short)41, message);
            } else {
                HandshakeMessageOutput message = new HandshakeMessageOutput((short)11);
                certificate.encode(context, message, endPointHash);
                message.send(this);
            }

            securityParameters.localCertificate = certificate;
        }
    }

    protected void send13CertificateMessage(Certificate certificate) throws IOException {
        if (null == certificate) {
            throw new TlsFatalAlert((short)80);
        } else {
            TlsContext context = this.getContext();
            SecurityParameters securityParameters = context.getSecurityParametersHandshake();
            if (null != securityParameters.getLocalCertificate()) {
                throw new TlsFatalAlert((short)80);
            } else {
                HandshakeMessageOutput message = new HandshakeMessageOutput((short)11);
                certificate.encode(context, message, (OutputStream)null);
                message.send(this);
                securityParameters.localCertificate = certificate;
            }
        }
    }

    protected void send13CertificateVerifyMessage(DigitallySigned certificateVerify) throws IOException {
        HandshakeMessageOutput message = new HandshakeMessageOutput((short)15);
        certificateVerify.encode(message);
        message.send(this);
    }

    protected void sendChangeCipherSpec() throws IOException {
        this.sendChangeCipherSpecMessage();
        this.recordStream.enablePendingCipherWrite();
    }

    protected void sendChangeCipherSpecMessage() throws IOException {
        byte[] message = new byte[]{1};
        this.safeWriteRecord((short)20, message, 0, message.length);
    }

    protected void sendFinishedMessage() throws IOException {
        TlsContext context = this.getContext();
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        boolean isServerContext = context.isServer();
        byte[] verify_data = TlsUtils.calculateVerifyData(context, this.handshakeHash, isServerContext);
        securityParameters.localVerifyData = verify_data;
        if ((!this.resumedSession || securityParameters.isExtendedMasterSecret()) && null == securityParameters.getPeerVerifyData()) {
            securityParameters.tlsUnique = verify_data;
        }

        HandshakeMessageOutput.send(this, (short)20, verify_data);
    }

    protected void send13FinishedMessage() throws IOException {
        TlsContext context = this.getContext();
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        boolean isServerContext = context.isServer();
        byte[] verify_data = TlsUtils.calculateVerifyData(context, this.handshakeHash, isServerContext);
        securityParameters.localVerifyData = verify_data;
        securityParameters.tlsUnique = null;
        HandshakeMessageOutput.send(this, (short)20, verify_data);
    }

    protected void send13KeyUpdate(boolean updateRequested) throws IOException {
        if (this.appDataReady && this.keyUpdateEnabled) {
            short requestUpdate = (short) (updateRequested ? 1 : 0);
            HandshakeMessageOutput.send(this, (short)24, TlsUtils.encodeUint8((short)requestUpdate));
            TlsUtils.update13TrafficSecretLocal(this.getContext());
            this.recordStream.notifyKeyUpdateSent();
            this.keyUpdatePendingSend &= updateRequested;
        } else {
            throw new TlsFatalAlert((short)80);
        }
    }

    protected void sendSupplementalDataMessage(Vector supplementalData) throws IOException {
        HandshakeMessageOutput message = new HandshakeMessageOutput((short)23);
        writeSupplementalData(message, supplementalData);
        message.send(this);
    }

    public void close() throws IOException {
        this.handleClose(true);
    }

    public void flush() throws IOException {
    }

    boolean isApplicationDataReady() {
        return this.appDataReady;
    }

    public boolean isClosed() {
        return this.closed;
    }

    public boolean isConnected() {
        if (this.closed) {
            return false;
        } else {
            AbstractTlsContext context = this.getContextAdmin();
            return null != context && context.isConnected();
        }
    }

    public boolean isHandshaking() {
        if (this.closed) {
            return false;
        } else {
            AbstractTlsContext context = this.getContextAdmin();
            return null != context && context.isHandshaking();
        }
    }

    protected short processMaxFragmentLengthExtension(Hashtable clientExtensions, Hashtable serverExtensions, short alertDescription) throws IOException {
        short maxFragmentLength = TlsExtensionsUtils.getMaxFragmentLengthExtension(serverExtensions);
        if (maxFragmentLength < 0 || MaxFragmentLength.isValid(maxFragmentLength) && (this.resumedSession || maxFragmentLength == TlsExtensionsUtils.getMaxFragmentLengthExtension(clientExtensions))) {
            return maxFragmentLength;
        } else {
            throw new TlsFatalAlert(alertDescription);
        }
    }

    protected void refuseRenegotiation() throws IOException {
        if (TlsUtils.isSSL(this.getContext())) {
            throw new TlsFatalAlert((short)40);
        } else {
            this.raiseAlertWarning((short)100, "Renegotiation not supported");
        }
    }

    protected static void assertEmpty(ByteArrayInputStream buf) throws IOException {
        if (buf.available() > 0) {
            throw new TlsFatalAlert((short)50);
        }
    }

    protected static byte[] createRandomBlock(boolean useGMTUnixTime, TlsContext context) {
        byte[] result = context.getNonceGenerator().generateNonce(32);
        if (useGMTUnixTime) {
            TlsUtils.writeGMTUnixTime(result, 0);
        }

        return result;
    }

    protected static byte[] createRenegotiationInfo(byte[] renegotiated_connection) throws IOException {
        return TlsUtils.encodeOpaque8(renegotiated_connection);
    }

    protected static void establishMasterSecret(TlsContext context, TlsKeyExchange keyExchange) throws IOException {
        TlsSecret preMasterSecret = keyExchange.generatePreMasterSecret();
        if (preMasterSecret == null) {
            throw new TlsFatalAlert((short)80);
        } else {
            try {
                context.getSecurityParametersHandshake().masterSecret = TlsUtils.calculateMasterSecret(context, preMasterSecret);
            } finally {
                preMasterSecret.destroy();
            }

        }
    }

    protected static Hashtable readExtensions(ByteArrayInputStream input) throws IOException {
        if (input.available() < 1) {
            return null;
        } else {
            byte[] extBytes = TlsUtils.readOpaque16(input);
            assertEmpty(input);
            return readExtensionsData(extBytes);
        }
    }

    protected static Hashtable readExtensionsData(byte[] extBytes) throws IOException {
        Hashtable extensions = new Hashtable();
        if (extBytes.length > 0) {
            ByteArrayInputStream buf = new ByteArrayInputStream(extBytes);

            do {
                int extension_type = TlsUtils.readUint16(buf);
                byte[] extension_data = TlsUtils.readOpaque16(buf);
                if (null != extensions.put(Integers.valueOf(extension_type), extension_data)) {
                    throw new TlsFatalAlert((short)47, "Repeated extension: " + ExtensionType.getText(extension_type));
                }
            } while(buf.available() > 0);
        }

        return extensions;
    }

    protected static Hashtable readExtensionsData13(int handshakeType, byte[] extBytes) throws IOException {
        Hashtable extensions = new Hashtable();
        if (extBytes.length > 0) {
            ByteArrayInputStream buf = new ByteArrayInputStream(extBytes);

            do {
                int extension_type = TlsUtils.readUint16(buf);
                if (!TlsUtils.isPermittedExtensionType13(handshakeType, extension_type)) {
                    throw new TlsFatalAlert((short)47, "Invalid extension: " + ExtensionType.getText(extension_type));
                }

                byte[] extension_data = TlsUtils.readOpaque16(buf);
                if (null != extensions.put(Integers.valueOf(extension_type), extension_data)) {
                    throw new TlsFatalAlert((short)47, "Repeated extension: " + ExtensionType.getText(extension_type));
                }
            } while(buf.available() > 0);
        }

        return extensions;
    }

    protected static Hashtable readExtensionsDataClientHello(byte[] extBytes) throws IOException {
        Hashtable extensions = new Hashtable();
        if (extBytes.length > 0) {
            ByteArrayInputStream buf = new ByteArrayInputStream(extBytes);
            boolean pre_shared_key_found = false;

            while(true) {
                int extension_type = TlsUtils.readUint16(buf);
                byte[] extension_data = TlsUtils.readOpaque16(buf);
                if (null != extensions.put(Integers.valueOf(extension_type), extension_data)) {
                    throw new TlsFatalAlert((short)47, "Repeated extension: " + ExtensionType.getText(extension_type));
                }

                pre_shared_key_found |= 41 == extension_type;
                if (buf.available() <= 0) {
                    if (pre_shared_key_found && 41 != extension_type) {
                        throw new TlsFatalAlert((short)47, "'pre_shared_key' MUST be last in ClientHello");
                    }
                    break;
                }
            }
        }

        return extensions;
    }

    protected static Vector readSupplementalDataMessage(ByteArrayInputStream input) throws IOException {
        byte[] supp_data = TlsUtils.readOpaque24(input, 1);
        assertEmpty(input);
        ByteArrayInputStream buf = new ByteArrayInputStream(supp_data);
        Vector supplementalData = new Vector();

        while(buf.available() > 0) {
            int supp_data_type = TlsUtils.readUint16(buf);
            byte[] data = TlsUtils.readOpaque16(buf);
            supplementalData.addElement(new SupplementalDataEntry(supp_data_type, data));
        }

        return supplementalData;
    }

    protected static void writeExtensions(OutputStream output, Hashtable extensions) throws IOException {
        writeExtensions(output, extensions, 0);
    }

    protected static void writeExtensions(OutputStream output, Hashtable extensions, int bindersSize) throws IOException {
        if (null != extensions && !extensions.isEmpty()) {
            byte[] extBytes = writeExtensionsData(extensions, bindersSize);
            int lengthWithBinders = extBytes.length + bindersSize;
            TlsUtils.checkUint16(lengthWithBinders);
            TlsUtils.writeUint16(lengthWithBinders, output);
            output.write(extBytes);
        }
    }

    protected static byte[] writeExtensionsData(Hashtable extensions) throws IOException {
        return writeExtensionsData(extensions, 0);
    }

    protected static byte[] writeExtensionsData(Hashtable extensions, int bindersSize) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writeExtensionsData(extensions, bindersSize, buf);
        return buf.toByteArray();
    }

    protected static void writeExtensionsData(Hashtable extensions, int bindersSize, ByteArrayOutputStream buf) throws IOException {
        writeSelectedExtensions(buf, extensions, true);
        writeSelectedExtensions(buf, extensions, false);
        writePreSharedKeyExtension(buf, extensions, bindersSize);
    }

    protected static void writePreSharedKeyExtension(OutputStream output, Hashtable extensions, int bindersSize) throws IOException {
        byte[] extension_data = (byte[])((byte[])extensions.get(TlsExtensionsUtils.EXT_pre_shared_key));
        if (null != extension_data) {
            TlsUtils.checkUint16(41);
            TlsUtils.writeUint16(41, output);
            int lengthWithBinders = extension_data.length + bindersSize;
            TlsUtils.checkUint16(lengthWithBinders);
            TlsUtils.writeUint16(lengthWithBinders, output);
            output.write(extension_data);
        }

    }

    protected static void writeSelectedExtensions(OutputStream output, Hashtable extensions, boolean selectEmpty) throws IOException {
        Enumeration keys = extensions.keys();

        while(keys.hasMoreElements()) {
            Integer key = (Integer)keys.nextElement();
            int extension_type = key;
            if (41 != extension_type) {
                byte[] extension_data = (byte[])((byte[])extensions.get(key));
                if (selectEmpty == (extension_data.length == 0)) {
                    TlsUtils.checkUint16(extension_type);
                    TlsUtils.writeUint16(extension_type, output);
                    TlsUtils.writeOpaque16(extension_data, output);
                }
            }
        }

    }

    protected static void writeSupplementalData(OutputStream output, Vector supplementalData) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        for(int i = 0; i < supplementalData.size(); ++i) {
            SupplementalDataEntry entry = (SupplementalDataEntry)supplementalData.elementAt(i);
            int supp_data_type = entry.getDataType();
            TlsUtils.checkUint16(supp_data_type);
            TlsUtils.writeUint16(supp_data_type, buf);
            TlsUtils.writeOpaque16(entry.getData(), buf);
        }

        byte[] supp_data = buf.toByteArray();
        TlsUtils.writeOpaque24(supp_data, output);
    }
}