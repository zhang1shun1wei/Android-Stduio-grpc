package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TrustedAuthority {
    protected Object identifier;
    protected short identifierType;

    public TrustedAuthority(short identifierType2, Object identifier2) {
        if (!isCorrectType(identifierType2, identifier2)) {
            throw new IllegalArgumentException("'identifier' is not an instance of the correct type");
        }
        this.identifierType = identifierType2;
        this.identifier = identifier2;
    }

    public short getIdentifierType() {
        return this.identifierType;
    }

    public Object getIdentifier() {
        return this.identifier;
    }

    public byte[] getCertSHA1Hash() {
        return Arrays.clone((byte[]) this.identifier);
    }

    public byte[] getKeySHA1Hash() {
        return Arrays.clone((byte[]) this.identifier);
    }

    public X500Name getX509Name() {
        checkCorrectType((short) 2);
        return (X500Name) this.identifier;
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeUint8(this.identifierType, output);
        switch (this.identifierType) {
            case 0:
                return;
            case 1:
            case 3:
                output.write((byte[]) this.identifier);
                return;
            case 2:
                TlsUtils.writeOpaque16(((X500Name) this.identifier).getEncoded("DER"), output);
                return;
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    public static TrustedAuthority parse(InputStream input) throws IOException {
        Object obj;
        short identifier_type = TlsUtils.readUint8(input);
        switch (identifier_type) {
            case 0:
                obj = null;
                break;
            case 1:
            case 3:
                obj = TlsUtils.readFully(20, input);
                break;
            case 2:
                byte[] derEncoding = TlsUtils.readOpaque16(input, 1);
                X500Name x500Name = X500Name.getInstance(TlsUtils.readASN1Object(derEncoding));
                TlsUtils.requireDEREncoding(x500Name, derEncoding);
                obj = x500Name;
                break;
            default:
                throw new TlsFatalAlert((short) 50);
        }
        return new TrustedAuthority(identifier_type, obj);
    }

    /* access modifiers changed from: protected */
    public void checkCorrectType(short expectedIdentifierType) {
        if (this.identifierType != expectedIdentifierType || !isCorrectType(expectedIdentifierType, this.identifier)) {
            throw new IllegalStateException("TrustedAuthority is not of type " + IdentifierType.getName(expectedIdentifierType));
        }
    }

    protected static boolean isCorrectType(short identifierType2, Object identifier2) {
        switch (identifierType2) {
            case 0:
                return identifier2 == null;
            case 1:
            case 3:
                return isSHA1Hash(identifier2);
            case 2:
                return identifier2 instanceof X500Name;
            default:
                throw new IllegalArgumentException("'identifierType' is an unsupported IdentifierType");
        }
    }

    protected static boolean isSHA1Hash(Object identifier2) {
        return (identifier2 instanceof byte[]) && ((byte[]) identifier2).length == 20;
    }
}
