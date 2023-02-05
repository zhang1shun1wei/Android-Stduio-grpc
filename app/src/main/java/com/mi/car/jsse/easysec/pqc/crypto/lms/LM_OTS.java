package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

/* access modifiers changed from: package-private */
public class LM_OTS {
    static final short D_MESG = -32383;
    private static final short D_PBLC = -32640;
    private static final int ITER_J = 22;
    private static final int ITER_K = 20;
    private static final int ITER_PREV = 23;
    static final int MAX_HASH = 32;
    static final int SEED_LEN = 32;
    static final int SEED_RANDOMISER_INDEX = -3;

    LM_OTS() {
    }

    public static int coef(byte[] S, int i, int w) {
        return (S[(i * w) / 8] >>> (w * ((i ^ -1) & ((8 / w) - 1)))) & ((1 << w) - 1);
    }

    public static int cksm(byte[] S, int sLen, LMOtsParameters parameters) {
        int sum = 0;
        int twoWpow = (1 << parameters.getW()) - 1;
        for (int i = 0; i < (sLen * 8) / parameters.getW(); i++) {
            sum = (sum + twoWpow) - coef(S, i, parameters.getW());
        }
        return sum << parameters.getLs();
    }

    public static LMOtsPublicKey lms_ots_generatePublicKey(LMOtsPrivateKey privateKey) {
        return new LMOtsPublicKey(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), lms_ots_generatePublicKey(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), privateKey.getMasterSecret()));
    }

    static byte[] lms_ots_generatePublicKey(LMOtsParameters parameter, byte[] I, int q, byte[] masterSecret) {
        Digest publicContext = DigestUtil.getDigest(parameter.getDigestOID());
        byte[] prehashPrefix = Composer.compose().bytes(I).u32str(q).u16str(-32640).padUntil(0, 22).build();
        publicContext.update(prehashPrefix, 0, prehashPrefix.length);
        Digest ctx = DigestUtil.getDigest(parameter.getDigestOID());
        byte[] buf = Composer.compose().bytes(I).u32str(q).padUntil(0, ctx.getDigestSize() + 23).build();
        SeedDerive derive = new SeedDerive(I, masterSecret, DigestUtil.getDigest(parameter.getDigestOID()));
        derive.setQ(q);
        derive.setJ(0);
        int p = parameter.getP();
        int n = parameter.getN();
        int twoToWminus1 = (1 << parameter.getW()) - 1;
        int i = 0;
        while (i < p) {
            derive.deriveSeed(buf, i < p + -1, 23);
            Pack.shortToBigEndian((short) i, buf, 20);
            for (int j = 0; j < twoToWminus1; j++) {
                buf[22] = (byte) j;
                ctx.update(buf, 0, buf.length);
                ctx.doFinal(buf, 23);
            }
            publicContext.update(buf, 23, n);
            i++;
        }
        byte[] K = new byte[publicContext.getDigestSize()];
        publicContext.doFinal(K, 0);
        return K;
    }

    public static LMOtsSignature lm_ots_generate_signature(LMSigParameters sigParams, LMOtsPrivateKey privateKey, byte[][] path, byte[] message, boolean preHashed) {
        byte[] C;
        byte[] Q = new byte[34];
        if (!preHashed) {
            LMSContext qCtx = privateKey.getSignatureContext(sigParams, path);
            LmsUtils.byteArray(message, 0, message.length, qCtx);
            C = qCtx.getC();
            Q = qCtx.getQ();
        } else {
            C = new byte[32];
            System.arraycopy(message, 0, Q, 0, privateKey.getParameter().getN());
        }
        return lm_ots_generate_signature(privateKey, Q, C);
    }

    public static LMOtsSignature lm_ots_generate_signature(LMOtsPrivateKey privateKey, byte[] Q, byte[] C) {
        LMOtsParameters parameter = privateKey.getParameter();
        int n = parameter.getN();
        int p = parameter.getP();
        int w = parameter.getW();
        byte[] sigComposer = new byte[(p * n)];
        Digest ctx = DigestUtil.getDigest(parameter.getDigestOID());
        SeedDerive derive = privateKey.getDerivationFunction();
        int cs = cksm(Q, n, parameter);
        Q[n] = (byte) ((cs >>> 8) & GF2Field.MASK);
        Q[n + 1] = (byte) cs;
        byte[] tmp = Composer.compose().bytes(privateKey.getI()).u32str(privateKey.getQ()).padUntil(0, n + 23).build();
        derive.setJ(0);
        int i = 0;
        while (i < p) {
            Pack.shortToBigEndian((short) i, tmp, 20);
            derive.deriveSeed(tmp, i < p + -1, 23);
            int a = coef(Q, i, w);
            for (int j = 0; j < a; j++) {
                tmp[22] = (byte) j;
                ctx.update(tmp, 0, n + 23);
                ctx.doFinal(tmp, 23);
            }
            System.arraycopy(tmp, 23, sigComposer, n * i, n);
            i++;
        }
        return new LMOtsSignature(parameter, C, sigComposer);
    }

    public static boolean lm_ots_validate_signature(LMOtsPublicKey publicKey, LMOtsSignature signature, byte[] message, boolean prehashed) throws LMSException {
        if (signature.getType().equals(publicKey.getParameter())) {
            return Arrays.areEqual(lm_ots_validate_signature_calculate(publicKey, signature, message), publicKey.getK());
        }
        throw new LMSException("public key and signature ots types do not match");
    }

    public static byte[] lm_ots_validate_signature_calculate(LMOtsPublicKey publicKey, LMOtsSignature signature, byte[] message) {
        LMSContext ctx = publicKey.createOtsContext(signature);
        LmsUtils.byteArray(message, ctx);
        return lm_ots_validate_signature_calculate(ctx);
    }

    public static byte[] lm_ots_validate_signature_calculate(LMSContext context) {
        LMOtsSignature signature;
        LMOtsPublicKey publicKey = context.getPublicKey();
        LMOtsParameters parameter = publicKey.getParameter();
        Object sig = context.getSignature();
        if (sig instanceof LMSSignature) {
            signature = ((LMSSignature) sig).getOtsSignature();
        } else {
            signature = (LMOtsSignature) sig;
        }
        int n = parameter.getN();
        int w = parameter.getW();
        int p = parameter.getP();
        byte[] Q = context.getQ();
        int cs = cksm(Q, n, parameter);
        Q[n] = (byte) ((cs >>> 8) & GF2Field.MASK);
        Q[n + 1] = (byte) cs;
        byte[] I = publicKey.getI();
        int q = publicKey.getQ();
        Digest finalContext = DigestUtil.getDigest(parameter.getDigestOID());
        LmsUtils.byteArray(I, finalContext);
        LmsUtils.u32str(q, finalContext);
        LmsUtils.u16str(D_PBLC, finalContext);
        byte[] tmp = Composer.compose().bytes(I).u32str(q).padUntil(0, n + 23).build();
        int max_digit = (1 << w) - 1;
        byte[] y = signature.getY();
        Digest ctx = DigestUtil.getDigest(parameter.getDigestOID());
        for (int i = 0; i < p; i++) {
            Pack.shortToBigEndian((short) i, tmp, 20);
            System.arraycopy(y, i * n, tmp, 23, n);
            for (int j = coef(Q, i, w); j < max_digit; j++) {
                tmp[22] = (byte) j;
                ctx.update(tmp, 0, n + 23);
                ctx.doFinal(tmp, 23);
            }
            finalContext.update(tmp, 23, n);
        }
        byte[] K = new byte[n];
        finalContext.doFinal(K, 0);
        return K;
    }
}
