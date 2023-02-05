package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.pqc.crypto.ExhaustedPrivateKeyException;
import java.util.Arrays;
import java.util.List;

class HSS {
    HSS() {
    }

    public static HSSPrivateKeyParameters generateHSSKeyPair(HSSKeyGenerationParameters parameters) {
        LMSPrivateKeyParameters[] keys = new LMSPrivateKeyParameters[parameters.getDepth()];
        LMSSignature[] sig = new LMSSignature[(parameters.getDepth() - 1)];
        byte[] rootSeed = new byte[32];
        parameters.getRandom().nextBytes(rootSeed);
        byte[] I = new byte[16];
        parameters.getRandom().nextBytes(I);
        byte[] zero = new byte[0];
        long hssKeyMaxIndex = 1;
        for (int t = 0; t < keys.length; t++) {
            if (t == 0) {
                keys[t] = new LMSPrivateKeyParameters(parameters.getLmsParameters()[t].getLMSigParam(), parameters.getLmsParameters()[t].getLMOTSParam(), 0, I, 1 << parameters.getLmsParameters()[t].getLMSigParam().getH(), rootSeed);
            } else {
                keys[t] = new PlaceholderLMSPrivateKey(parameters.getLmsParameters()[t].getLMSigParam(), parameters.getLmsParameters()[t].getLMOTSParam(), -1, zero, 1 << parameters.getLmsParameters()[t].getLMSigParam().getH(), zero);
            }
            hssKeyMaxIndex *= (long) (1 << parameters.getLmsParameters()[t].getLMSigParam().getH());
        }
        if (hssKeyMaxIndex == 0) {
            hssKeyMaxIndex = Long.MAX_VALUE;
        }
        return new HSSPrivateKeyParameters(parameters.getDepth(), Arrays.asList(keys), Arrays.asList(sig), 0, hssKeyMaxIndex);
    }

    public static void incrementIndex(HSSPrivateKeyParameters keyPair) {
        synchronized (keyPair) {
            rangeTestKeys(keyPair);
            keyPair.incIndex();
            keyPair.getKeys().get(keyPair.getL() - 1).incIndex();
        }
    }

    static void rangeTestKeys(HSSPrivateKeyParameters keyPair) {
        String str;
        synchronized (keyPair) {
            if (keyPair.getIndex() >= keyPair.getIndexLimit()) {
                StringBuilder append = new StringBuilder().append("hss private key");
                if (keyPair.isShard()) {
                    str = " shard";
                } else {
                    str = "";
                }
                throw new ExhaustedPrivateKeyException(append.append(str).append(" is exhausted").toString());
            }
            int L = keyPair.getL();
            int d = L;
            List<LMSPrivateKeyParameters> prv = keyPair.getKeys();
            while (prv.get(d - 1).getIndex() == (1 << prv.get(d - 1).getSigParameters().getH())) {
                d--;
                if (d == 0) {
                    throw new ExhaustedPrivateKeyException("hss private key" + (keyPair.isShard() ? " shard" : "") + " is exhausted the maximum limit for this HSS private key");
                }
            }
            while (d < L) {
                keyPair.replaceConsumedKey(d);
                d++;
            }
        }
    }

    public static HSSSignature generateSignature(HSSPrivateKeyParameters keyPair, byte[] message) {
        LMSPrivateKeyParameters nextKey;
        LMSSignedPubKey[] signed_pub_key;
        int L = keyPair.getL();
        synchronized (keyPair) {
            rangeTestKeys(keyPair);
            List<LMSPrivateKeyParameters> keys = keyPair.getKeys();
            List<LMSSignature> sig = keyPair.getSig();
            nextKey = keyPair.getKeys().get(L - 1);
            signed_pub_key = new LMSSignedPubKey[(L - 1)];
            for (int i = 0; i < L - 1; i++) {
                signed_pub_key[i] = new LMSSignedPubKey(sig.get(i), keys.get(i + 1).getPublicKey());
            }
            keyPair.incIndex();
        }
        LMSContext context = nextKey.generateLMSContext().withSignedPublicKeys(signed_pub_key);
        context.update(message, 0, message.length);
        return generateSignature(L, context);
    }

    public static HSSSignature generateSignature(int L, LMSContext context) {
        return new HSSSignature(L - 1, context.getSignedPubKeys(), LMS.generateSign(context));
    }

    public static boolean verifySignature(HSSPublicKeyParameters publicKey, HSSSignature signature, byte[] message) {
        int Nspk = signature.getlMinus1();
        if (Nspk + 1 != publicKey.getL()) {
            return false;
        }
        LMSSignature[] sigList = new LMSSignature[(Nspk + 1)];
        LMSPublicKeyParameters[] pubList = new LMSPublicKeyParameters[Nspk];
        for (int i = 0; i < Nspk; i++) {
            sigList[i] = signature.getSignedPubKey()[i].getSignature();
            pubList[i] = signature.getSignedPubKey()[i].getPublicKey();
        }
        sigList[Nspk] = signature.getSignature();
        LMSPublicKeyParameters key = publicKey.getLMSPublicKey();
        for (int i2 = 0; i2 < Nspk; i2++) {
            if (!LMS.verifySignature(key, sigList[i2], pubList[i2].toByteArray())) {
                return false;
            }
            try {
                key = pubList[i2];
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }
        return LMS.verifySignature(key, sigList[Nspk], message);
    }

    static class PlaceholderLMSPrivateKey extends LMSPrivateKeyParameters {
        public PlaceholderLMSPrivateKey(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I, int maxQ, byte[] masterSecret) {
            super(lmsParameter, otsParameters, q, I, maxQ, masterSecret);
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPrivateKeyParameters
        public LMOtsPrivateKey getNextOtsPrivateKey() {
            throw new RuntimeException("placeholder only");
        }

        @Override // com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPrivateKeyParameters
        public LMSPublicKeyParameters getPublicKey() {
            throw new RuntimeException("placeholder only");
        }
    }
}
