package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.GrpcClient;
import com.mi.car.jsse.easysec.extend.drive.TeeX509Native;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsSigner;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SignatureException;

public class JcaTlsECDSA13Signer implements TlsSigner {
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final int signatureScheme;

    public JcaTlsECDSA13Signer(JcaTlsCrypto crypto2, PrivateKey privateKey2, int signatureScheme2) {
        if (crypto2 == null) {
            throw new NullPointerException("crypto");
        } else if (privateKey2 == null) {
            throw new NullPointerException("privateKey");
        } else if (!SignatureScheme.isECDSA(signatureScheme2)) {
            throw new IllegalArgumentException("signatureScheme");
        } else {
            this.crypto = crypto2;
            this.privateKey = privateKey2;
            this.signatureScheme = signatureScheme2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        if (algorithm == null || SignatureScheme.from(algorithm) != this.signatureScheme) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        try {
            byte[] hashBytes = GrpcClient.getSingleton().generateSignature(hash);
//            byte[] hashBytes = TeeX509Native.generateSignatureJNI(hash);
            String s = new String(hashBytes, "UTF-8");
            if (hashBytes != null) {
                return hashBytes;
            }
            throw new SignatureException("调用jni签名接口返回错误");
        } catch (GeneralSecurityException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException {
        return null;
    }
}
