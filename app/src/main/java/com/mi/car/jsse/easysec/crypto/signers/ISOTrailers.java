package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import com.mi.car.jsse.easysec.util.Integers;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ISOTrailers {
    public static final int TRAILER_IMPLICIT = 188;
    public static final int TRAILER_RIPEMD128 = 13004;
    public static final int TRAILER_RIPEMD160 = 12748;
    public static final int TRAILER_SHA1 = 13260;
    public static final int TRAILER_SHA224 = 14540;
    public static final int TRAILER_SHA256 = 13516;
    public static final int TRAILER_SHA384 = 14028;
    public static final int TRAILER_SHA512 = 13772;
    public static final int TRAILER_SHA512_224 = 14796;
    public static final int TRAILER_SHA512_256 = 15052;
    public static final int TRAILER_WHIRLPOOL = 14284;
    private static final Map<String, Integer> trailerMap;

    static {
        Map<String, Integer> trailers = new HashMap<>();
        trailers.put("RIPEMD128", Integers.valueOf(13004));
        trailers.put("RIPEMD160", Integers.valueOf(12748));
        trailers.put(McElieceCCA2KeyGenParameterSpec.SHA1, Integers.valueOf(13260));
        trailers.put(McElieceCCA2KeyGenParameterSpec.SHA224, Integers.valueOf(14540));
        trailers.put("SHA-256", Integers.valueOf(13516));
        trailers.put(McElieceCCA2KeyGenParameterSpec.SHA384, Integers.valueOf(14028));
        trailers.put("SHA-512", Integers.valueOf(13772));
        trailers.put("SHA-512/224", Integers.valueOf(TRAILER_SHA512_224));
        trailers.put(SPHINCSKeyParameters.SHA512_256, Integers.valueOf(TRAILER_SHA512_256));
        trailers.put("Whirlpool", Integers.valueOf(14284));
        trailerMap = Collections.unmodifiableMap(trailers);
    }

    public static Integer getTrailer(Digest digest) {
        return trailerMap.get(digest.getAlgorithmName());
    }

    public static boolean noTrailerAvailable(Digest digest) {
        return !trailerMap.containsKey(digest.getAlgorithmName());
    }
}
