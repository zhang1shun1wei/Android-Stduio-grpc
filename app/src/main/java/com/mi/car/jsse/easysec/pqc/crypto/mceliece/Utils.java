package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA1Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA224Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA384Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;

class Utils {
    Utils() {
    }

    static Digest getDigest(String digestName) {
        if (digestName.equals(McElieceCCA2KeyGenParameterSpec.SHA1)) {
            return new SHA1Digest();
        }
        if (digestName.equals(McElieceCCA2KeyGenParameterSpec.SHA224)) {
            return new SHA224Digest();
        }
        if (digestName.equals("SHA-256")) {
            return new SHA256Digest();
        }
        if (digestName.equals(McElieceCCA2KeyGenParameterSpec.SHA384)) {
            return new SHA384Digest();
        }
        if (digestName.equals("SHA-512")) {
            return new SHA512Digest();
        }
        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
    }
}
