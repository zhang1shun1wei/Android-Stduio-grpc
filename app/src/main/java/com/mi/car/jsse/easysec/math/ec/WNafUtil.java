package com.mi.car.jsse.easysec.math.ec;

import java.math.BigInteger;

public abstract class WNafUtil {
    private static final int[] DEFAULT_WINDOW_SIZE_CUTOFFS = {13, 41, 121, 337, 897, 2305};
    private static final byte[] EMPTY_BYTES = new byte[0];
    private static final int[] EMPTY_INTS = new int[0];
    private static final ECPoint[] EMPTY_POINTS = new ECPoint[0];
    private static final int MAX_WIDTH = 16;
    public static final String PRECOMP_NAME = "bc_wnaf";

    public static void configureBasepoint(ECPoint p) {
        ECCurve c = p.getCurve();
        if (c != null) {
            BigInteger n = c.getOrder();
            final int confWidth = Math.min(16, getWindowSize(n == null ? c.getFieldSize() + 1 : n.bitLength()) + 3);
            c.precompute(p, PRECOMP_NAME, new PreCompCallback() {
                /* class com.mi.car.jsse.easysec.math.ec.WNafUtil.AnonymousClass1 */

                @Override // com.mi.car.jsse.easysec.math.ec.PreCompCallback
                public PreCompInfo precompute(PreCompInfo existing) {
                    WNafPreCompInfo existingWNaf = existing instanceof WNafPreCompInfo ? (WNafPreCompInfo) existing : null;
                    if (existingWNaf == null || existingWNaf.getConfWidth() != confWidth) {
                        WNafPreCompInfo result = new WNafPreCompInfo();
                        result.setPromotionCountdown(0);
                        result.setConfWidth(confWidth);
                        if (existingWNaf != null) {
                            result.setPreComp(existingWNaf.getPreComp());
                            result.setPreCompNeg(existingWNaf.getPreCompNeg());
                            result.setTwice(existingWNaf.getTwice());
                            result.setWidth(existingWNaf.getWidth());
                        }
                        return result;
                    }
                    existingWNaf.setPromotionCountdown(0);
                    return existingWNaf;
                }
            });
        }
    }

    public static int[] generateCompactNaf(BigInteger k) {
        int digit;
        int length;
        if ((k.bitLength() >>> 16) != 0) {
            throw new IllegalArgumentException("'k' must have bitlength < 2^16");
        } else if (k.signum() == 0) {
            return EMPTY_INTS;
        } else {
            BigInteger _3k = k.shiftLeft(1).add(k);
            int bits = _3k.bitLength();
            int[] naf = new int[(bits >> 1)];
            BigInteger diff = _3k.xor(k);
            int highBit = bits - 1;
            int zeroes = 0;
            int i = 1;
            int length2 = 0;
            while (i < highBit) {
                if (!diff.testBit(i)) {
                    zeroes++;
                    length = length2;
                } else {
                    if (k.testBit(i)) {
                        digit = -1;
                    } else {
                        digit = 1;
                    }
                    length = length2 + 1;
                    naf[length2] = (digit << 16) | zeroes;
                    zeroes = 1;
                    i++;
                }
                i++;
                length2 = length;
            }
            int length3 = length2 + 1;
            naf[length2] = 65536 | zeroes;
            if (naf.length > length3) {
                return trim(naf, length3);
            }
            return naf;
        }
    }

    public static int[] generateCompactWindowNaf(int width, BigInteger k) {
        int zeroes;
        if (width == 2) {
            return generateCompactNaf(k);
        }
        if (width < 2 || width > 16) {
            throw new IllegalArgumentException("'width' must be in the range [2, 16]");
        } else if ((k.bitLength() >>> 16) != 0) {
            throw new IllegalArgumentException("'k' must have bitlength < 2^16");
        } else if (k.signum() == 0) {
            return EMPTY_INTS;
        } else {
            int[] wnaf = new int[((k.bitLength() / width) + 1)];
            int pow2 = 1 << width;
            int mask = pow2 - 1;
            int sign = pow2 >>> 1;
            boolean carry = false;
            int length = 0;
            int pos = 0;
            while (pos <= k.bitLength()) {
                if (k.testBit(pos) == carry) {
                    pos++;
                } else {
                    k = k.shiftRight(pos);
                    int digit = k.intValue() & mask;
                    if (carry) {
                        digit++;
                    }
                    carry = (digit & sign) != 0;
                    if (carry) {
                        digit -= pow2;
                    }
                    if (length > 0) {
                        zeroes = pos - 1;
                    } else {
                        zeroes = pos;
                    }
                    wnaf[length] = (digit << 16) | zeroes;
                    pos = width;
                    length++;
                }
            }
            if (wnaf.length > length) {
                return trim(wnaf, length);
            }
            return wnaf;
        }
    }

    public static byte[] generateJSF(BigInteger g, BigInteger h) {
        byte[] jsf = new byte[(Math.max(g.bitLength(), h.bitLength()) + 1)];
        BigInteger k0 = g;
        BigInteger k1 = h;
        int j = 0;
        int d0 = 0;
        int d1 = 0;
        int offset = 0;
        while (true) {
            if ((d0 | d1) == 0 && k0.bitLength() <= offset && k1.bitLength() <= offset) {
                break;
            }
            int n0 = ((k0.intValue() >>> offset) + d0) & 7;
            int n1 = ((k1.intValue() >>> offset) + d1) & 7;
            int u0 = n0 & 1;
            if (u0 != 0) {
                u0 -= n0 & 2;
                if (n0 + u0 == 4 && (n1 & 3) == 2) {
                    u0 = -u0;
                }
            }
            int u1 = n1 & 1;
            if (u1 != 0) {
                u1 -= n1 & 2;
                if (n1 + u1 == 4 && (n0 & 3) == 2) {
                    u1 = -u1;
                }
            }
            if ((d0 << 1) == u0 + 1) {
                d0 ^= 1;
            }
            if ((d1 << 1) == u1 + 1) {
                d1 ^= 1;
            }
            offset++;
            if (offset == 30) {
                offset = 0;
                k0 = k0.shiftRight(30);
                k1 = k1.shiftRight(30);
            }
            j++;
            jsf[j] = (byte) ((u0 << 4) | (u1 & 15));
        }
        if (jsf.length > j) {
            return trim(jsf, j);
        }
        return jsf;
    }

    public static byte[] generateNaf(BigInteger k) {
        int i;
        if (k.signum() == 0) {
            return EMPTY_BYTES;
        }
        BigInteger _3k = k.shiftLeft(1).add(k);
        int digits = _3k.bitLength() - 1;
        byte[] naf = new byte[digits];
        BigInteger diff = _3k.xor(k);
        int i2 = 1;
        while (i2 < digits) {
            if (diff.testBit(i2)) {
                int i3 = i2 - 1;
                if (k.testBit(i2)) {
                    i = -1;
                } else {
                    i = 1;
                }
                naf[i3] = (byte) i;
                i2++;
            }
            i2++;
        }
        naf[digits - 1] = 1;
        return naf;
    }

    public static byte[] generateWindowNaf(int width, BigInteger k) {
        if (width == 2) {
            return generateNaf(k);
        }
        if (width < 2 || width > 8) {
            throw new IllegalArgumentException("'width' must be in the range [2, 8]");
        } else if (k.signum() == 0) {
            return EMPTY_BYTES;
        } else {
            byte[] wnaf = new byte[(k.bitLength() + 1)];
            int pow2 = 1 << width;
            int mask = pow2 - 1;
            int sign = pow2 >>> 1;
            boolean carry = false;
            int length = 0;
            int pos = 0;
            while (pos <= k.bitLength()) {
                if (k.testBit(pos) == carry) {
                    pos++;
                } else {
                    k = k.shiftRight(pos);
                    int digit = k.intValue() & mask;
                    if (carry) {
                        digit++;
                    }
                    carry = (digit & sign) != 0;
                    if (carry) {
                        digit -= pow2;
                    }
                    if (length > 0) {
                        pos--;
                    }
                    int length2 = length + pos;
                    wnaf[length2] = (byte) digit;
                    pos = width;
                    length = length2 + 1;
                }
            }
            if (wnaf.length > length) {
                return trim(wnaf, length);
            }
            return wnaf;
        }
    }

    public static int getNafWeight(BigInteger k) {
        if (k.signum() == 0) {
            return 0;
        }
        return k.shiftLeft(1).add(k).xor(k).bitCount();
    }

    public static WNafPreCompInfo getWNafPreCompInfo(ECPoint p) {
        return getWNafPreCompInfo(p.getCurve().getPreCompInfo(p, PRECOMP_NAME));
    }

    public static WNafPreCompInfo getWNafPreCompInfo(PreCompInfo preCompInfo) {
        if (preCompInfo instanceof WNafPreCompInfo) {
            return (WNafPreCompInfo) preCompInfo;
        }
        return null;
    }

    public static int getWindowSize(int bits) {
        return getWindowSize(bits, DEFAULT_WINDOW_SIZE_CUTOFFS, 16);
    }

    public static int getWindowSize(int bits, int maxWidth) {
        return getWindowSize(bits, DEFAULT_WINDOW_SIZE_CUTOFFS, maxWidth);
    }

    public static int getWindowSize(int bits, int[] windowSizeCutoffs) {
        return getWindowSize(bits, windowSizeCutoffs, 16);
    }

    public static int getWindowSize(int bits, int[] windowSizeCutoffs, int maxWidth) {
        int w = 0;
        while (w < windowSizeCutoffs.length && bits >= windowSizeCutoffs[w]) {
            w++;
        }
        return Math.max(2, Math.min(maxWidth, w + 2));
    }

    public static WNafPreCompInfo precompute(final ECPoint p, final int minWidth, final boolean includeNegated) {
        final ECCurve c = p.getCurve();
        return (WNafPreCompInfo) c.precompute(p, PRECOMP_NAME, new PreCompCallback() {
            /* class com.mi.car.jsse.easysec.math.ec.WNafUtil.AnonymousClass2 */

            @Override // com.mi.car.jsse.easysec.math.ec.PreCompCallback
            public PreCompInfo precompute(PreCompInfo existing) {
                int pos;
                WNafPreCompInfo existingWNaf = existing instanceof WNafPreCompInfo ? (WNafPreCompInfo) existing : null;
                int width = Math.max(2, Math.min(16, minWidth));
                if (checkExisting(existingWNaf, width, 1 << (width - 2), includeNegated)) {
                    existingWNaf.decrementPromotionCountdown();
                    return existingWNaf;
                }
                WNafPreCompInfo result = new WNafPreCompInfo();
                ECPoint[] preComp = null;
                ECPoint[] preCompNeg = null;
                ECPoint twiceP = null;
                if (existingWNaf != null) {
                    result.setPromotionCountdown(existingWNaf.decrementPromotionCountdown());
                    result.setConfWidth(existingWNaf.getConfWidth());
                    preComp = existingWNaf.getPreComp();
                    preCompNeg = existingWNaf.getPreCompNeg();
                    twiceP = existingWNaf.getTwice();
                }
                int width2 = Math.min(16, Math.max(result.getConfWidth(), width));
                int reqPreCompLen = 1 << (width2 - 2);
                int iniPreCompLen = 0;
                if (preComp == null) {
                    preComp = WNafUtil.EMPTY_POINTS;
                } else {
                    iniPreCompLen = preComp.length;
                }
                if (iniPreCompLen < reqPreCompLen) {
                    preComp = WNafUtil.resizeTable(preComp, reqPreCompLen);
                    if (reqPreCompLen == 1) {
                        preComp[0] = p.normalize();
                    } else {
                        int curPreCompLen = iniPreCompLen;
                        if (curPreCompLen == 0) {
                            preComp[0] = p;
                            curPreCompLen = 1;
                        }
                        ECFieldElement iso = null;
                        if (reqPreCompLen == 2) {
                            preComp[1] = p.threeTimes();
                        } else {
                            ECPoint isoTwiceP = twiceP;
                            ECPoint last = preComp[curPreCompLen - 1];
                            if (isoTwiceP == null) {
                                isoTwiceP = preComp[0].twice();
                                twiceP = isoTwiceP;
                                if (!twiceP.isInfinity() && ECAlgorithms.isFpCurve(c) && c.getFieldSize() >= 64) {
                                    switch (c.getCoordinateSystem()) {
                                        case 2:
                                        case 3:
                                        case 4:
                                            iso = twiceP.getZCoord(0);
                                            isoTwiceP = c.createPoint(twiceP.getXCoord().toBigInteger(), twiceP.getYCoord().toBigInteger());
                                            ECFieldElement iso2 = iso.square();
                                            last = last.scaleX(iso2).scaleY(iso2.multiply(iso));
                                            if (iniPreCompLen == 0) {
                                                preComp[0] = last;
                                                break;
                                            }
                                            break;
                                    }
                                }
                            }
                            while (curPreCompLen < reqPreCompLen) {
                                curPreCompLen++;
                                last = last.add(isoTwiceP);
                                preComp[curPreCompLen] = last;
                            }
                        }
                        c.normalizeAll(preComp, iniPreCompLen, reqPreCompLen - iniPreCompLen, iso);
                    }
                }
                if (includeNegated) {
                    if (preCompNeg == null) {
                        pos = 0;
                        preCompNeg = new ECPoint[reqPreCompLen];
                    } else {
                        pos = preCompNeg.length;
                        if (pos < reqPreCompLen) {
                            preCompNeg = WNafUtil.resizeTable(preCompNeg, reqPreCompLen);
                        }
                    }
                    while (pos < reqPreCompLen) {
                        preCompNeg[pos] = preComp[pos].negate();
                        pos++;
                    }
                }
                result.setPreComp(preComp);
                result.setPreCompNeg(preCompNeg);
                result.setTwice(twiceP);
                result.setWidth(width2);
                return result;
            }

            private boolean checkExisting(WNafPreCompInfo existingWNaf, int width, int reqPreCompLen, boolean includeNegated) {
                return existingWNaf != null && existingWNaf.getWidth() >= Math.max(existingWNaf.getConfWidth(), width) && checkTable(existingWNaf.getPreComp(), reqPreCompLen) && (!includeNegated || checkTable(existingWNaf.getPreCompNeg(), reqPreCompLen));
            }

            private boolean checkTable(ECPoint[] table, int reqLen) {
                return table != null && table.length >= reqLen;
            }
        });
    }

    public static WNafPreCompInfo precomputeWithPointMap(ECPoint p, final ECPointMap pointMap, final WNafPreCompInfo fromWNaf, final boolean includeNegated) {
        return (WNafPreCompInfo) p.getCurve().precompute(p, PRECOMP_NAME, new PreCompCallback() {
            /* class com.mi.car.jsse.easysec.math.ec.WNafUtil.AnonymousClass3 */

            @Override // com.mi.car.jsse.easysec.math.ec.PreCompCallback
            public PreCompInfo precompute(PreCompInfo existing) {
                WNafPreCompInfo existingWNaf = existing instanceof WNafPreCompInfo ? (WNafPreCompInfo) existing : null;
                int width = fromWNaf.getWidth();
                if (checkExisting(existingWNaf, width, fromWNaf.getPreComp().length, includeNegated)) {
                    existingWNaf.decrementPromotionCountdown();
                    return existingWNaf;
                }
                WNafPreCompInfo result = new WNafPreCompInfo();
                result.setPromotionCountdown(fromWNaf.getPromotionCountdown());
                ECPoint twiceFrom = fromWNaf.getTwice();
                if (twiceFrom != null) {
                    result.setTwice(pointMap.map(twiceFrom));
                }
                ECPoint[] preCompFrom = fromWNaf.getPreComp();
                ECPoint[] preComp = new ECPoint[preCompFrom.length];
                for (int i = 0; i < preCompFrom.length; i++) {
                    preComp[i] = pointMap.map(preCompFrom[i]);
                }
                result.setPreComp(preComp);
                result.setWidth(width);
                if (includeNegated) {
                    ECPoint[] preCompNeg = new ECPoint[preComp.length];
                    for (int i2 = 0; i2 < preCompNeg.length; i2++) {
                        preCompNeg[i2] = preComp[i2].negate();
                    }
                    result.setPreCompNeg(preCompNeg);
                }
                return result;
            }

            private boolean checkExisting(WNafPreCompInfo existingWNaf, int width, int reqPreCompLen, boolean includeNegated) {
                return existingWNaf != null && existingWNaf.getWidth() >= width && checkTable(existingWNaf.getPreComp(), reqPreCompLen) && (!includeNegated || checkTable(existingWNaf.getPreCompNeg(), reqPreCompLen));
            }

            private boolean checkTable(ECPoint[] table, int reqLen) {
                return table != null && table.length >= reqLen;
            }
        });
    }

    private static byte[] trim(byte[] a, int length) {
        byte[] result = new byte[length];
        System.arraycopy(a, 0, result, 0, result.length);
        return result;
    }

    private static int[] trim(int[] a, int length) {
        int[] result = new int[length];
        System.arraycopy(a, 0, result, 0, result.length);
        return result;
    }

    /* access modifiers changed from: private */
    public static ECPoint[] resizeTable(ECPoint[] a, int length) {
        ECPoint[] result = new ECPoint[length];
        System.arraycopy(a, 0, result, 0, a.length);
        return result;
    }
}
