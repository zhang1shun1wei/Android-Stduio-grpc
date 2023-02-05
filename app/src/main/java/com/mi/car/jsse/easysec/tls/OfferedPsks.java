package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import com.mi.car.jsse.easysec.tls.crypto.TlsHashOutputStream;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

public class OfferedPsks {
    protected final Vector binders;
    protected final int bindersSize;
    protected final Vector identities;

    /* access modifiers changed from: package-private */
    public static class BindersConfig {
        final int bindersSize;
        final TlsSecret[] earlySecrets;
        final short[] pskKeyExchangeModes;
        final TlsPSK[] psks;

        BindersConfig(TlsPSK[] psks2, short[] pskKeyExchangeModes2, TlsSecret[] earlySecrets2, int bindersSize2) {
            this.psks = psks2;
            this.pskKeyExchangeModes = pskKeyExchangeModes2;
            this.earlySecrets = earlySecrets2;
            this.bindersSize = bindersSize2;
        }
    }

    /* access modifiers changed from: package-private */
    public static class SelectedConfig {
        final TlsSecret earlySecret;
        final int index;
        final TlsPSK psk;
        final short[] pskKeyExchangeModes;

        SelectedConfig(int index2, TlsPSK psk2, short[] pskKeyExchangeModes2, TlsSecret earlySecret2) {
            this.index = index2;
            this.psk = psk2;
            this.pskKeyExchangeModes = pskKeyExchangeModes2;
            this.earlySecret = earlySecret2;
        }
    }

    public OfferedPsks(Vector identities2) {
        this(identities2, null, -1);
    }

    private OfferedPsks(Vector identities2, Vector binders2, int bindersSize2) {
        boolean z;
        boolean z2 = true;
        if (identities2 == null || identities2.isEmpty()) {
            throw new IllegalArgumentException("'identities' cannot be null or empty");
        } else if (binders2 == null || identities2.size() == binders2.size()) {
            if (binders2 != null) {
                z = true;
            } else {
                z = false;
            }
            if (z != (bindersSize2 < 0 ? false : z2)) {
                throw new IllegalArgumentException("'bindersSize' must be >= 0 iff 'binders' are present");
            }
            this.identities = identities2;
            this.binders = binders2;
            this.bindersSize = bindersSize2;
        } else {
            throw new IllegalArgumentException("'binders' must be the same length as 'identities' (or null)");
        }
    }

    public Vector getBinders() {
        return this.binders;
    }

    public int getBindersSize() {
        return this.bindersSize;
    }

    public Vector getIdentities() {
        return this.identities;
    }

    public int getIndexOfIdentity(PskIdentity pskIdentity) {
        int count = this.identities.size();
        for (int i = 0; i < count; i++) {
            if (pskIdentity.equals(this.identities.elementAt(i))) {
                return i;
            }
        }
        return -1;
    }

    public void encode(OutputStream output) throws IOException {
        int lengthOfIdentitiesList = 0;
        for (int i = 0; i < this.identities.size(); i++) {
            lengthOfIdentitiesList += ((PskIdentity) this.identities.elementAt(i)).getEncodedLength();
        }
        TlsUtils.checkUint16(lengthOfIdentitiesList);
        TlsUtils.writeUint16(lengthOfIdentitiesList, output);
        for (int i2 = 0; i2 < this.identities.size(); i2++) {
            ((PskIdentity) this.identities.elementAt(i2)).encode(output);
        }
        if (this.binders != null) {
            int lengthOfBindersList = 0;
            for (int i3 = 0; i3 < this.binders.size(); i3++) {
                lengthOfBindersList += ((byte[]) this.binders.elementAt(i3)).length + 1;
            }
            TlsUtils.checkUint16(lengthOfBindersList);
            TlsUtils.writeUint16(lengthOfBindersList, output);
            for (int i4 = 0; i4 < this.binders.size(); i4++) {
                TlsUtils.writeOpaque8((byte[]) this.binders.elementAt(i4), output);
            }
        }
    }

    static void encodeBinders(OutputStream output, TlsCrypto crypto, TlsHandshakeHash handshakeHash, BindersConfig bindersConfig) throws IOException {
        TlsPSK[] psks = bindersConfig.psks;
        TlsSecret[] earlySecrets = bindersConfig.earlySecrets;
        int expectedLengthOfBindersList = bindersConfig.bindersSize - 2;
        TlsUtils.checkUint16(expectedLengthOfBindersList);
        TlsUtils.writeUint16(expectedLengthOfBindersList, output);
        int lengthOfBindersList = 0;
        for (int i = 0; i < psks.length; i++) {
            TlsPSK psk = psks[i];
            TlsSecret earlySecret = earlySecrets[i];
            int pskCryptoHashAlgorithm = TlsCryptoUtils.getHashForPRF(psk.getPRFAlgorithm());
            TlsHash hash = crypto.createHash(pskCryptoHashAlgorithm);
            handshakeHash.copyBufferTo(new TlsHashOutputStream(hash));
            byte[] binder = TlsUtils.calculatePSKBinder(crypto, true, pskCryptoHashAlgorithm, earlySecret, hash.calculateHash());
            lengthOfBindersList += binder.length + 1;
            TlsUtils.writeOpaque8(binder, output);
        }
        if (expectedLengthOfBindersList != lengthOfBindersList) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    static int getBindersSize(TlsPSK[] psks) throws IOException {
        int lengthOfBindersList = 0;
        for (TlsPSK psk : psks) {
            lengthOfBindersList += TlsCryptoUtils.getHashOutputSize(TlsCryptoUtils.getHashForPRF(psk.getPRFAlgorithm())) + 1;
        }
        TlsUtils.checkUint16(lengthOfBindersList);
        return lengthOfBindersList + 2;
    }

    public static OfferedPsks parse(InputStream input) throws IOException {
        Vector identities2 = new Vector();
        int totalLengthIdentities = TlsUtils.readUint16(input);
        if (totalLengthIdentities < 7) {
            throw new TlsFatalAlert((short) 50);
        }
        ByteArrayInputStream buf = new ByteArrayInputStream(TlsUtils.readFully(totalLengthIdentities, input));
        do {
            identities2.add(PskIdentity.parse(buf));
        } while (buf.available() > 0);
        Vector binders2 = new Vector();
        int totalLengthBinders = TlsUtils.readUint16(input);
        if (totalLengthBinders < 33) {
            throw new TlsFatalAlert((short) 50);
        }
        ByteArrayInputStream buf2 = new ByteArrayInputStream(TlsUtils.readFully(totalLengthBinders, input));
        do {
            binders2.add(TlsUtils.readOpaque8(buf2, 32));
        } while (buf2.available() > 0);
        return new OfferedPsks(identities2, binders2, totalLengthBinders + 2);
    }
}
