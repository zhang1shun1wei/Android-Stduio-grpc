package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.StatelessProcessing;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;
import java.lang.reflect.Array;

public class AESEngine implements BlockCipher, StatelessProcessing {
    private static final int BLOCK_SIZE = 16;
    private static final byte[] S = {99, 124, 119, 123, -14, 107, 111, -59, 48, 1, 103, 43, -2, -41, -85, 118, -54, -126, -55, 125, -6, 89, 71, -16, -83, -44, -94, -81, -100, -92, 114, -64, -73, -3, -109, 38, 54, 63, -9, -52, 52, -91, -27, -15, 113, -40, 49, 21, 4, -57, 35, -61, 24, -106, 5, -102, 7, 18, Byte.MIN_VALUE, -30, -21, 39, -78, 117, 9, -125, 44, 26, 27, 110, 90, -96, 82, 59, -42, -77, 41, -29, 47, -124, 83, -47, 0, -19, 32, -4, -79, 91, 106, -53, -66, 57, 74, 76, 88, -49, -48, -17, -86, -5, 67, 77, 51, -123, 69, -7, 2, Byte.MAX_VALUE, 80, 60, -97, -88, 81, -93, 64, -113, -110, -99, 56, -11, PSSSigner.TRAILER_IMPLICIT, -74, -38, 33, Tnaf.POW_2_WIDTH, -1, -13, -46, -51, 12, 19, -20, 95, -105, 68, 23, -60, -89, 126, 61, 100, 93, 25, 115, 96, -127, 79, -36, 34, 42, -112, -120, 70, -18, -72, 20, -34, 94, 11, -37, -32, 50, 58, 10, 73, 6, 36, 92, -62, -45, -84, 98, -111, -107, -28, 121, -25, -56, 55, 109, -115, -43, 78, -87, 108, 86, -12, -22, 101, 122, -82, 8, -70, 120, 37, 46, 28, -90, -76, -58, -24, -35, 116, 31, 75, -67, -117, -118, 112, 62, -75, 102, 72, 3, -10, 14, 97, 53, 87, -71, -122, -63, 29, -98, -31, -8, -104, 17, 105, -39, -114, -108, -101, 30, -121, -23, -50, 85, 40, -33, -116, -95, -119, 13, -65, -26, 66, 104, 65, -103, 45, 15, -80, 84, -69, 22};
    private static final byte[] Si = {82, 9, 106, -43, 48, 54, -91, 56, -65, 64, -93, -98, -127, -13, -41, -5, 124, -29, 57, -126, -101, 47, -1, -121, 52, -114, 67, 68, -60, -34, -23, -53, 84, 123, -108, 50, -90, -62, 35, 61, -18, 76, -107, 11, 66, -6, -61, 78, 8, 46, -95, 102, 40, -39, 36, -78, 118, 91, -94, 73, 109, -117, -47, 37, 114, -8, -10, 100, -122, 104, -104, 22, -44, -92, 92, -52, 93, 101, -74, -110, 108, 112, 72, 80, -3, -19, -71, -38, 94, 21, 70, 87, -89, -115, -99, -124, -112, -40, -85, 0, -116, PSSSigner.TRAILER_IMPLICIT, -45, 10, -9, -28, 88, 5, -72, -77, 69, 6, -48, 44, 30, -113, -54, 63, 15, 2, -63, -81, -67, 3, 1, 19, -118, 107, 58, -111, 17, 65, 79, 103, -36, -22, -105, -14, -49, -50, -16, -76, -26, 115, -106, -84, 116, 34, -25, -83, 53, -123, -30, -7, 55, -24, 28, 117, -33, 110, 71, -15, 26, 113, 29, 41, -59, -119, 111, -73, 98, 14, -86, 24, -66, 27, -4, 86, 62, 75, -58, -46, 121, 32, -102, -37, -64, -2, 120, -51, 90, -12, 31, -35, -88, 51, -120, 7, -57, 49, -79, 18, Tnaf.POW_2_WIDTH, 89, 39, Byte.MIN_VALUE, -20, 95, 96, 81, Byte.MAX_VALUE, -87, 25, -75, 74, 13, 45, -27, 122, -97, -109, -55, -100, -17, -96, -32, 59, 77, -82, 42, -11, -80, -56, -21, -69, 60, -125, 83, -103, 97, 23, 43, 4, 126, -70, 119, -42, 38, -31, 105, 20, 99, 85, 33, 12, 125};
    private static final int[] T0 = {-1520213050, -2072216328, -1720223762, -1921287178, 234025727, -1117033514, -1318096930, 1422247313, 1345335392, 50397442, -1452841010, 2099981142, 436141799, 1658312629, -424957107, -1703512340, 1170918031, -1652391393, 1086966153, -2021818886, 368769775, -346465870, -918075506, 200339707, -324162239, 1742001331, -39673249, -357585083, -1080255453, -140204973, -1770884380, 1539358875, -1028147339, 486407649, -1366060227, 1780885068, 1513502316, 1094664062, 49805301, 1338821763, 1546925160, -190470831, 887481809, 150073849, -1821281822, 1943591083, 1395732834, 1058346282, 201589768, 1388824469, 1696801606, 1589887901, 672667696, -1583966665, 251987210, -1248159185, 151455502, 907153956, -1686077413, 1038279391, 652995533, 1764173646, -843926913, -1619692054, 453576978, -1635548387, 1949051992, 773462580, 756751158, -1301385508, -296068428, -73359269, -162377052, 1295727478, 1641469623, -827083907, 2066295122, 1055122397, 1898917726, -1752923117, -179088474, 1758581177, 0, 753790401, 1612718144, 536673507, -927878791, -312779850, -1100322092, 1187761037, -641810841, 1262041458, -565556588, -733197160, -396863312, 1255133061, 1808847035, 720367557, -441800113, 385612781, -985447546, -682799718, 1429418854, -1803188975, -817543798, 284817897, 100794884, -2122350594, -263171936, 1144798328, -1163944155, -475486133, -212774494, -22830243, -1069531008, -1970303227, -1382903233, -1130521311, 1211644016, 83228145, -541279133, -1044990345, 1977277103, 1663115586, 806359072, 452984805, 250868733, 1842533055, 1288555905, 336333848, 890442534, 804056259, -513843266, -1567123659, -867941240, 957814574, 1472513171, -223893675, -2105639172, 1195195770, -1402706744, -413311558, 723065138, -1787595802, -1604296512, -1736343271, -783331426, 2145180835, 1713513028, 2116692564, -1416589253, -2088204277, -901364084, 703524551, -742868885, 1007948840, 2044649127, -497131844, 487262998, 1994120109, 1004593371, 1446130276, 1312438900, 503974420, -615954030, 168166924, 1814307912, -463709000, 1573044895, 1859376061, -273896381, -1503501628, -1466855111, -1533700815, 937747667, -1954973198, 854058965, 1137232011, 1496790894, -1217565222, -1936880383, 1691735473, -766620004, -525751991, -1267962664, -95005012, 133494003, 636152527, -1352309302, -1904575756, -374428089, 403179536, -709182865, -2005370640, 1864705354, 1915629148, 605822008, -240736681, -944458637, 1371981463, 602466507, 2094914977, -1670089496, 555687742, -582268010, -591544991, -2037675251, -2054518257, -1871679264, 1111375484, -994724495, -1436129588, -666351472, 84083462, 32962295, 302911004, -1553899070, 1597322602, -111716434, -793134743, -1853454825, 1489093017, 656219450, -1180787161, 954327513, 335083755, -1281845205, 856756514, -1150719534, 1893325225, -1987146233, -1483434957, -1231316179, 572399164, -1836611819, 552200649, 1238290055, -11184726, 2015897680, 2061492133, -1886614525, -123625127, -2138470135, 386731290, -624967835, 837215959, -968736124, -1201116976, -1019133566, -1332111063, 1999449434, 286199582, -877612933, -61582168, -692339859, 974525996};
    private static final int[] Tinv0 = {1353184337, 1399144830, -1012656358, -1772214470, -882136261, -247096033, -1420232020, -1828461749, 1442459680, -160598355, -1854485368, 625738485, -52959921, -674551099, -2143013594, -1885117771, 1230680542, 1729870373, -1743852987, -507445667, 41234371, 317738113, -1550367091, -956705941, -413167869, -1784901099, -344298049, -631680363, 763608788, -752782248, 694804553, 1154009486, 1787413109, 2021232372, 1799248025, -579749593, -1236278850, 397248752, 1722556617, -1271214467, 407560035, -2110711067, 1613975959, 1165972322, -529046351, -2068943941, 480281086, -1809118983, 1483229296, 436028815, -2022908268, -1208452270, 601060267, -503166094, 1468997603, 715871590, 120122290, 63092015, -1703164538, -1526188077, -226023376, -1297760477, -1167457534, 1552029421, 723308426, -1833666137, -252573709, -1578997426, -839591323, -708967162, 526529745, -1963022652, -1655493068, -1604979806, 853641733, 1978398372, 971801355, -1427152832, 111112542, 1360031421, -108388034, 1023860118, -1375387939, 1186850381, -1249028975, 90031217, 1876166148, -15380384, 620468249, -1746289194, -868007799, 2006899047, -1119688528, -2004121337, 945494503, -605108103, 1191869601, -384875908, -920746760, 0, -2088337399, 1223502642, -1401941730, 1316117100, -67170563, 1446544655, 517320253, 658058550, 1691946762, 564550760, -783000677, 976107044, -1318647284, 266819475, -761860428, -1634624741, 1338359936, -1574904735, 1766553434, 370807324, 179999714, -450191168, 1138762300, 488053522, 185403662, -1379431438, -1180125651, -928440812, -2061897385, 1275557295, -1143105042, -44007517, -1624899081, -1124765092, -985962940, 880737115, 1982415755, -590994485, 1761406390, 1676797112, -891538985, 277177154, 1076008723, 538035844, 2099530373, -130171950, 288553390, 1839278535, 1261411869, -214912292, -330136051, -790380169, 1813426987, -1715900247, -95906799, 577038663, -997393240, 440397984, -668172970, -275762398, -951170681, -1043253031, -22885748, 906744984, -813566554, 685669029, 646887386, -1530942145, -459458004, 227702864, -1681105046, 1648787028, -1038905866, -390539120, 1593260334, -173030526, -1098883681, 2090061929, -1456614033, -1290656305, 999926984, -1484974064, 1852021992, 2075868123, 158869197, -199730834, 28809964, -1466282109, 1701746150, 2129067946, 147831841, -420997649, -644094022, -835293366, -737566742, -696471511, -1347247055, 824393514, 815048134, -1067015627, 935087732, -1496677636, -1328508704, 366520115, 1251476721, -136647615, 240176511, 804688151, -1915335306, 1303441219, 1414376140, -553347356, -474623586, 461924940, -1205916479, 2136040774, 82468509, 1563790337, 1937016826, 776014843, 1511876531, 1389550482, 861278441, 323475053, -1939744870, 2047648055, -1911228327, -1992551445, -299390514, 902390199, -303751967, 1018251130, 1507840668, 1064563285, 2043548696, -1086863501, -355600557, 1537932639, 342834655, -2032450440, -2114736182, 1053059257, 741614648, 1598071746, 1925389590, 203809468, -1958134744, 1100287487, 1895934009, -558691320, -1662733096, -1866377628, 1636092795, 1890988757, 1952214088, 1113045200};
    private static final int m1 = -2139062144;
    private static final int m2 = 2139062143;
    private static final int m3 = 27;
    private static final int m4 = -1061109568;
    private static final int m5 = 1061109567;
    private static final int[] rcon = {1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145};
    private int ROUNDS;
    private int[][] WorkingKey = null;
    private boolean forEncryption;
    private byte[] s;

    private static int shift(int r, int shift) {
        return (r >>> shift) | (r << (-shift));
    }

    private static int FFmulX(int x) {
        return ((m2 & x) << 1) ^ (((m1 & x) >>> 7) * 27);
    }

    private static int FFmulX2(int x) {
        int t0 = (m5 & x) << 2;
        int t1 = x & m4;
        int t12 = t1 ^ (t1 >>> 1);
        return ((t12 >>> 2) ^ t0) ^ (t12 >>> 5);
    }

    private static int inv_mcol(int x) {
        int t1 = x ^ shift(x, 8);
        int t0 = x ^ FFmulX(t1);
        int t12 = t1 ^ FFmulX2(t0);
        return t0 ^ (shift(t12, 16) ^ t12);
    }

    private static int subWord(int x) {
        return (S[x & GF2Field.MASK] & 255) | ((S[(x >> 8) & GF2Field.MASK] & 255) << 8) | ((S[(x >> 16) & GF2Field.MASK] & 255) << 16) | (S[(x >> 24) & GF2Field.MASK] << 24);
    }

    private int[][] generateWorkingKey(byte[] key, boolean forEncryption2) {
        int keyLen = key.length;
        if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0) {
            throw new IllegalArgumentException("Key length not 128/192/256 bits.");
        }
        int KC = keyLen >>> 2;
        this.ROUNDS = KC + 6;
        int[][] W = (int[][]) Array.newInstance(Integer.TYPE, this.ROUNDS + 1, 4);
        switch (KC) {
            case 4:
                int col0 = Pack.littleEndianToInt(key, 0);
                W[0][0] = col0;
                int col1 = Pack.littleEndianToInt(key, 4);
                W[0][1] = col1;
                int col2 = Pack.littleEndianToInt(key, 8);
                W[0][2] = col2;
                int col3 = Pack.littleEndianToInt(key, 12);
                W[0][3] = col3;
                for (int i = 1; i <= 10; i++) {
                    col0 ^= subWord(shift(col3, 8)) ^ rcon[i - 1];
                    W[i][0] = col0;
                    col1 ^= col0;
                    W[i][1] = col1;
                    col2 ^= col1;
                    W[i][2] = col2;
                    col3 ^= col2;
                    W[i][3] = col3;
                }
                break;
            case 5:
            case 7:
            default:
                throw new IllegalStateException("Should never get here");
            case 6:
                int col02 = Pack.littleEndianToInt(key, 0);
                W[0][0] = col02;
                int col12 = Pack.littleEndianToInt(key, 4);
                W[0][1] = col12;
                int col22 = Pack.littleEndianToInt(key, 8);
                W[0][2] = col22;
                int col32 = Pack.littleEndianToInt(key, 12);
                W[0][3] = col32;
                int col4 = Pack.littleEndianToInt(key, 16);
                int col5 = Pack.littleEndianToInt(key, 20);
                int i2 = 1;
                int rcon2 = 1;
                while (true) {
                    W[i2][0] = col4;
                    W[i2][1] = col5;
                    int colx = subWord(shift(col5, 8)) ^ rcon2;
                    int rcon3 = rcon2 << 1;
                    int col03 = col02 ^ colx;
                    W[i2][2] = col03;
                    int col13 = col12 ^ col03;
                    W[i2][3] = col13;
                    int col23 = col22 ^ col13;
                    W[i2 + 1][0] = col23;
                    int col33 = col32 ^ col23;
                    W[i2 + 1][1] = col33;
                    int col42 = col4 ^ col33;
                    W[i2 + 1][2] = col42;
                    int col52 = col5 ^ col42;
                    W[i2 + 1][3] = col52;
                    int colx2 = subWord(shift(col52, 8)) ^ rcon3;
                    rcon2 = rcon3 << 1;
                    col02 = col03 ^ colx2;
                    W[i2 + 2][0] = col02;
                    col12 = col13 ^ col02;
                    W[i2 + 2][1] = col12;
                    col22 = col23 ^ col12;
                    W[i2 + 2][2] = col22;
                    col32 = col33 ^ col22;
                    W[i2 + 2][3] = col32;
                    i2 += 3;
                    if (i2 >= 13) {
                        break;
                    } else {
                        col4 = col42 ^ col32;
                        col5 = col52 ^ col4;
                    }
                }
            case 8:
                int col04 = Pack.littleEndianToInt(key, 0);
                W[0][0] = col04;
                int col14 = Pack.littleEndianToInt(key, 4);
                W[0][1] = col14;
                int col24 = Pack.littleEndianToInt(key, 8);
                W[0][2] = col24;
                int col34 = Pack.littleEndianToInt(key, 12);
                W[0][3] = col34;
                int col43 = Pack.littleEndianToInt(key, 16);
                W[1][0] = col43;
                int col53 = Pack.littleEndianToInt(key, 20);
                W[1][1] = col53;
                int col6 = Pack.littleEndianToInt(key, 24);
                W[1][2] = col6;
                int col7 = Pack.littleEndianToInt(key, 28);
                W[1][3] = col7;
                int i3 = 2;
                int rcon4 = 1;
                while (true) {
                    int colx3 = subWord(shift(col7, 8)) ^ rcon4;
                    rcon4 <<= 1;
                    col04 ^= colx3;
                    W[i3][0] = col04;
                    col14 ^= col04;
                    W[i3][1] = col14;
                    col24 ^= col14;
                    W[i3][2] = col24;
                    col34 ^= col24;
                    W[i3][3] = col34;
                    int i4 = i3 + 1;
                    if (i4 >= 15) {
                        break;
                    } else {
                        col43 ^= subWord(col34);
                        W[i4][0] = col43;
                        col53 ^= col43;
                        W[i4][1] = col53;
                        col6 ^= col53;
                        W[i4][2] = col6;
                        col7 ^= col6;
                        W[i4][3] = col7;
                        i3 = i4 + 1;
                    }
                }
        }
        if (!forEncryption2) {
            for (int j = 1; j < this.ROUNDS; j++) {
                for (int i5 = 0; i5 < 4; i5++) {
                    W[j][i5] = inv_mcol(W[j][i5]);
                }
            }
        }
        return W;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption2, CipherParameters params) {
        if (params instanceof KeyParameter) {
            this.WorkingKey = generateWorkingKey(((KeyParameter) params).getKey(), forEncryption2);
            this.forEncryption = forEncryption2;
            if (forEncryption2) {
                this.s = Arrays.clone(S);
            } else {
                this.s = Arrays.clone(Si);
            }
        } else {
            throw new IllegalArgumentException("invalid parameter passed to AES init - " + params.getClass().getName());
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "AES";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (this.WorkingKey == null) {
            throw new IllegalStateException("AES engine not initialised");
        } else if (inOff > in.length - 16) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff > out.length - 16) {
            throw new OutputLengthException("output buffer too short");
        } else if (this.forEncryption) {
            encryptBlock(in, inOff, out, outOff, this.WorkingKey);
            return 16;
        } else {
            decryptBlock(in, inOff, out, outOff, this.WorkingKey);
            return 16;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }

    private void encryptBlock(byte[] in, int inOff, byte[] out, int outOff, int[][] KW) {
        int C0 = Pack.littleEndianToInt(in, inOff + 0);
        int C1 = Pack.littleEndianToInt(in, inOff + 4);
        int C2 = Pack.littleEndianToInt(in, inOff + 8);
        int C3 = Pack.littleEndianToInt(in, inOff + 12);
        int t0 = C0 ^ KW[0][0];
        int t1 = C1 ^ KW[0][1];
        int t2 = C2 ^ KW[0][2];
        int r = 1;
        int r3 = C3 ^ KW[0][3];
        while (r < this.ROUNDS - 1) {
            int r0 = (((T0[t0 & GF2Field.MASK] ^ shift(T0[(t1 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(t2 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(r3 >> 24) & GF2Field.MASK], 8)) ^ KW[r][0];
            int r1 = (((T0[t1 & GF2Field.MASK] ^ shift(T0[(t2 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(r3 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(t0 >> 24) & GF2Field.MASK], 8)) ^ KW[r][1];
            int r2 = (((T0[t2 & GF2Field.MASK] ^ shift(T0[(r3 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(t0 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(t1 >> 24) & GF2Field.MASK], 8)) ^ KW[r][2];
            int r4 = r + 1;
            int r32 = (((T0[r3 & GF2Field.MASK] ^ shift(T0[(t0 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(t1 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(t2 >> 24) & GF2Field.MASK], 8)) ^ KW[r][3];
            t0 = (((T0[r0 & GF2Field.MASK] ^ shift(T0[(r1 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(r2 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(r32 >> 24) & GF2Field.MASK], 8)) ^ KW[r4][0];
            t1 = (((T0[r1 & GF2Field.MASK] ^ shift(T0[(r2 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(r32 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(r0 >> 24) & GF2Field.MASK], 8)) ^ KW[r4][1];
            t2 = (((T0[r2 & GF2Field.MASK] ^ shift(T0[(r32 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(r0 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(r1 >> 24) & GF2Field.MASK], 8)) ^ KW[r4][2];
            r = r4 + 1;
            r3 = (((T0[r32 & GF2Field.MASK] ^ shift(T0[(r0 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(r1 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(r2 >> 24) & GF2Field.MASK], 8)) ^ KW[r4][3];
        }
        int r02 = (((T0[t0 & GF2Field.MASK] ^ shift(T0[(t1 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(t2 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(r3 >> 24) & GF2Field.MASK], 8)) ^ KW[r][0];
        int r12 = (((T0[t1 & GF2Field.MASK] ^ shift(T0[(t2 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(r3 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(t0 >> 24) & GF2Field.MASK], 8)) ^ KW[r][1];
        int r22 = (((T0[t2 & GF2Field.MASK] ^ shift(T0[(r3 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(t0 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(t1 >> 24) & GF2Field.MASK], 8)) ^ KW[r][2];
        int r5 = r + 1;
        int r33 = (((T0[r3 & GF2Field.MASK] ^ shift(T0[(t0 >> 8) & GF2Field.MASK], 24)) ^ shift(T0[(t1 >> 16) & GF2Field.MASK], 16)) ^ shift(T0[(t2 >> 24) & GF2Field.MASK], 8)) ^ KW[r][3];
        int C02 = ((((S[r02 & GF2Field.MASK] & 255) ^ ((S[(r12 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((this.s[(r22 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (this.s[(r33 >> 24) & GF2Field.MASK] << 24)) ^ KW[r5][0];
        int C12 = ((((this.s[r12 & GF2Field.MASK] & 255) ^ ((S[(r22 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r33 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (this.s[(r02 >> 24) & GF2Field.MASK] << 24)) ^ KW[r5][1];
        int C22 = ((((this.s[r22 & GF2Field.MASK] & 255) ^ ((S[(r33 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r02 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r12 >> 24) & GF2Field.MASK] << 24)) ^ KW[r5][2];
        int C32 = ((((this.s[r33 & GF2Field.MASK] & 255) ^ ((this.s[(r02 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((this.s[(r12 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r22 >> 24) & GF2Field.MASK] << 24)) ^ KW[r5][3];
        Pack.intToLittleEndian(C02, out, outOff + 0);
        Pack.intToLittleEndian(C12, out, outOff + 4);
        Pack.intToLittleEndian(C22, out, outOff + 8);
        Pack.intToLittleEndian(C32, out, outOff + 12);
    }

    private void decryptBlock(byte[] in, int inOff, byte[] out, int outOff, int[][] KW) {
        int C0 = Pack.littleEndianToInt(in, inOff + 0);
        int C1 = Pack.littleEndianToInt(in, inOff + 4);
        int C2 = Pack.littleEndianToInt(in, inOff + 8);
        int C3 = Pack.littleEndianToInt(in, inOff + 12);
        int t0 = C0 ^ KW[this.ROUNDS][0];
        int t1 = C1 ^ KW[this.ROUNDS][1];
        int t2 = C2 ^ KW[this.ROUNDS][2];
        int r = this.ROUNDS - 1;
        int r3 = C3 ^ KW[this.ROUNDS][3];
        int r2 = r;
        while (r2 > 1) {
            int r0 = (((Tinv0[t0 & GF2Field.MASK] ^ shift(Tinv0[(r3 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(t2 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(t1 >> 24) & GF2Field.MASK], 8)) ^ KW[r2][0];
            int r1 = (((Tinv0[t1 & GF2Field.MASK] ^ shift(Tinv0[(t0 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(r3 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(t2 >> 24) & GF2Field.MASK], 8)) ^ KW[r2][1];
            int r22 = (((Tinv0[t2 & GF2Field.MASK] ^ shift(Tinv0[(t1 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(t0 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(r3 >> 24) & GF2Field.MASK], 8)) ^ KW[r2][2];
            int r4 = r2 - 1;
            int r32 = (((Tinv0[r3 & GF2Field.MASK] ^ shift(Tinv0[(t2 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(t1 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(t0 >> 24) & GF2Field.MASK], 8)) ^ KW[r2][3];
            t0 = (((Tinv0[r0 & GF2Field.MASK] ^ shift(Tinv0[(r32 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(r22 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(r1 >> 24) & GF2Field.MASK], 8)) ^ KW[r4][0];
            t1 = (((Tinv0[r1 & GF2Field.MASK] ^ shift(Tinv0[(r0 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(r32 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(r22 >> 24) & GF2Field.MASK], 8)) ^ KW[r4][1];
            t2 = (((Tinv0[r22 & GF2Field.MASK] ^ shift(Tinv0[(r1 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(r0 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(r32 >> 24) & GF2Field.MASK], 8)) ^ KW[r4][2];
            r2 = r4 - 1;
            r3 = (((Tinv0[r32 & GF2Field.MASK] ^ shift(Tinv0[(r22 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(r1 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(r0 >> 24) & GF2Field.MASK], 8)) ^ KW[r4][3];
        }
        int r02 = (((Tinv0[t0 & GF2Field.MASK] ^ shift(Tinv0[(r3 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(t2 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(t1 >> 24) & GF2Field.MASK], 8)) ^ KW[r2][0];
        int r12 = (((Tinv0[t1 & GF2Field.MASK] ^ shift(Tinv0[(t0 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(r3 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(t2 >> 24) & GF2Field.MASK], 8)) ^ KW[r2][1];
        int r23 = (((Tinv0[t2 & GF2Field.MASK] ^ shift(Tinv0[(t1 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(t0 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(r3 >> 24) & GF2Field.MASK], 8)) ^ KW[r2][2];
        int r33 = (((Tinv0[r3 & GF2Field.MASK] ^ shift(Tinv0[(t2 >> 8) & GF2Field.MASK], 24)) ^ shift(Tinv0[(t1 >> 16) & GF2Field.MASK], 16)) ^ shift(Tinv0[(t0 >> 24) & GF2Field.MASK], 8)) ^ KW[r2][3];
        int C02 = ((((Si[r02 & GF2Field.MASK] & 255) ^ ((this.s[(r33 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((this.s[(r23 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r12 >> 24) & GF2Field.MASK] << 24)) ^ KW[0][0];
        int C12 = ((((this.s[r12 & GF2Field.MASK] & 255) ^ ((this.s[(r02 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r33 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (this.s[(r23 >> 24) & GF2Field.MASK] << 24)) ^ KW[0][1];
        int C22 = ((((this.s[r23 & GF2Field.MASK] & 255) ^ ((Si[(r12 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r02 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (this.s[(r33 >> 24) & GF2Field.MASK] << 24)) ^ KW[0][2];
        int C32 = ((((Si[r33 & GF2Field.MASK] & 255) ^ ((this.s[(r23 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((this.s[(r12 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (this.s[(r02 >> 24) & GF2Field.MASK] << 24)) ^ KW[0][3];
        Pack.intToLittleEndian(C02, out, outOff + 0);
        Pack.intToLittleEndian(C12, out, outOff + 4);
        Pack.intToLittleEndian(C22, out, outOff + 8);
        Pack.intToLittleEndian(C32, out, outOff + 12);
    }

    @Override // com.mi.car.jsse.easysec.crypto.StatelessProcessing
    public BlockCipher newInstance() {
        return new AESEngine();
    }
}
