package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.Digest;

/* access modifiers changed from: package-private */
public class LMS {
    static final short D_INTR = -31869;
    static final short D_LEAF = -32126;

    LMS() {
    }

    public static LMSPrivateKeyParameters generateKeys(LMSigParameters parameterSet, LMOtsParameters lmOtsParameters, int q, byte[] I, byte[] rootSeed) throws IllegalArgumentException {
        if (rootSeed != null && rootSeed.length >= parameterSet.getM()) {
            return new LMSPrivateKeyParameters(parameterSet, lmOtsParameters, q, I, 1 << parameterSet.getH(), rootSeed);
        }
        throw new IllegalArgumentException("root seed is less than " + parameterSet.getM());
    }

    public static LMSSignature generateSign(LMSPrivateKeyParameters privateKey, byte[] message) {
        LMSContext context = privateKey.generateLMSContext();
        context.update(message, 0, message.length);
        return generateSign(context);
    }

    public static LMSSignature generateSign(LMSContext context) {
        return new LMSSignature(context.getPrivateKey().getQ(), LM_OTS.lm_ots_generate_signature(context.getPrivateKey(), context.getQ(), context.getC()), context.getSigParams(), context.getPath());
    }

    public static boolean verifySignature(LMSPublicKeyParameters publicKey, LMSSignature S, byte[] message) {
        LMSContext context = publicKey.generateOtsContext(S);
        LmsUtils.byteArray(message, context);
        return verifySignature(publicKey, context);
    }

    public static boolean verifySignature(LMSPublicKeyParameters publicKey, byte[] S, byte[] message) {
        LMSContext context = publicKey.generateLMSContext(S);
        LmsUtils.byteArray(message, context);
        return verifySignature(publicKey, context);
    }

    public static boolean verifySignature(LMSPublicKeyParameters publicKey, LMSContext context) {
        LMSSignature S = (LMSSignature) context.getSignature();
        LMSigParameters lmsParameter = S.getParameter();
        int h = lmsParameter.getH();
        byte[][] path = S.getY();
        byte[] Kc = LM_OTS.lm_ots_validate_signature_calculate(context);
        int node_num = (1 << h) + S.getQ();
        byte[] I = publicKey.getI();
        Digest H = DigestUtil.getDigest(lmsParameter.getDigestOID());
        byte[] tmp = new byte[H.getDigestSize()];
        H.update(I, 0, I.length);
        LmsUtils.u32str(node_num, H);
        LmsUtils.u16str(D_LEAF, H);
        H.update(Kc, 0, Kc.length);
        H.doFinal(tmp, 0);
        int i = 0;
        while (node_num > 1) {
            if ((node_num & 1) == 1) {
                H.update(I, 0, I.length);
                LmsUtils.u32str(node_num / 2, H);
                LmsUtils.u16str(D_INTR, H);
                H.update(path[i], 0, path[i].length);
                H.update(tmp, 0, tmp.length);
                H.doFinal(tmp, 0);
            } else {
                H.update(I, 0, I.length);
                LmsUtils.u32str(node_num / 2, H);
                LmsUtils.u16str(D_INTR, H);
                H.update(tmp, 0, tmp.length);
                H.update(path[i], 0, path[i].length);
                H.doFinal(tmp, 0);
            }
            node_num /= 2;
            i++;
        }
        return publicKey.matchesT1(tmp);
    }
}
