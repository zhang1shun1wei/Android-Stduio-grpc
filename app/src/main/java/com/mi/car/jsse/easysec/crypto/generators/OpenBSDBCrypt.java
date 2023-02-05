package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.ByteArrayOutputStream;
import java.util.HashSet;
import java.util.Set;

public class OpenBSDBCrypt {
    private static final Set<String> allowedVersions = new HashSet();
    private static final byte[] decodingTable = new byte[128];
    private static final String defaultVersion = "2y";
    private static final byte[] encodingTable = {46, 47, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57};

    static {
        allowedVersions.add("2");
        allowedVersions.add("2x");
        allowedVersions.add("2a");
        allowedVersions.add(defaultVersion);
        allowedVersions.add("2b");
        for (int i = 0; i < decodingTable.length; i++) {
            decodingTable[i] = -1;
        }
        for (int i2 = 0; i2 < encodingTable.length; i2++) {
            decodingTable[encodingTable[i2]] = (byte) i2;
        }
    }

    private OpenBSDBCrypt() {
    }

    public static String generate(char[] password, byte[] salt, int cost) {
        return generate(defaultVersion, password, salt, cost);
    }

    public static String generate(byte[] password, byte[] salt, int cost) {
        return generate(defaultVersion, password, salt, cost);
    }

    public static String generate(String version, char[] password, byte[] salt, int cost) {
        if (password != null) {
            return doGenerate(version, Strings.toUTF8ByteArray(password), salt, cost);
        }
        throw new IllegalArgumentException("Password required.");
    }

    public static String generate(String version, byte[] password, byte[] salt, int cost) {
        if (password != null) {
            return doGenerate(version, Arrays.clone(password), salt, cost);
        }
        throw new IllegalArgumentException("Password required.");
    }

    private static String doGenerate(String version, byte[] psw, byte[] salt, int cost) {
        int i = 72;
        if (!allowedVersions.contains(version)) {
            throw new IllegalArgumentException("Version " + version + " is not accepted by this implementation.");
        } else if (salt == null) {
            throw new IllegalArgumentException("Salt required.");
        } else if (salt.length != 16) {
            throw new DataLengthException("16 byte salt required: " + salt.length);
        } else if (cost < 4 || cost > 31) {
            throw new IllegalArgumentException("Invalid cost factor.");
        } else {
            if (psw.length < 72) {
                i = psw.length + 1;
            }
            byte[] tmp = new byte[i];
            if (tmp.length > psw.length) {
                System.arraycopy(psw, 0, tmp, 0, psw.length);
            } else {
                System.arraycopy(psw, 0, tmp, 0, tmp.length);
            }
            Arrays.fill(psw, (byte) 0);
            String rv = createBcryptString(version, tmp, salt, cost);
            Arrays.fill(tmp, (byte) 0);
            return rv;
        }
    }

    public static boolean checkPassword(String bcryptString, char[] password) {
        if (password != null) {
            return doCheckPassword(bcryptString, Strings.toUTF8ByteArray(password));
        }
        throw new IllegalArgumentException("Missing password.");
    }

    public static boolean checkPassword(String bcryptString, byte[] password) {
        if (password != null) {
            return doCheckPassword(bcryptString, Arrays.clone(password));
        }
        throw new IllegalArgumentException("Missing password.");
    }

    private static boolean doCheckPassword(String bcryptString, byte[] password) {
        String version;
        int base;
        if (bcryptString == null) {
            throw new IllegalArgumentException("Missing bcryptString.");
        } else if (bcryptString.charAt(1) != '2') {
            throw new IllegalArgumentException("not a Bcrypt string");
        } else {
            int sLength = bcryptString.length();
            if (sLength == 60 || (sLength == 59 && bcryptString.charAt(2) == '$')) {
                if (bcryptString.charAt(2) == '$') {
                    if (!(bcryptString.charAt(0) == '$' && bcryptString.charAt(5) == '$')) {
                        throw new IllegalArgumentException("Invalid Bcrypt String format.");
                    }
                } else if (!(bcryptString.charAt(0) == '$' && bcryptString.charAt(3) == '$' && bcryptString.charAt(6) == '$')) {
                    throw new IllegalArgumentException("Invalid Bcrypt String format.");
                }
                if (bcryptString.charAt(2) == '$') {
                    version = bcryptString.substring(1, 2);
                    base = 3;
                } else {
                    version = bcryptString.substring(1, 3);
                    base = 4;
                }
                if (!allowedVersions.contains(version)) {
                    throw new IllegalArgumentException("Bcrypt version '" + version + "' is not supported by this implementation");
                }
                String costStr = bcryptString.substring(base, base + 2);
                try {
                    int cost = Integer.parseInt(costStr);
                    if (cost >= 4 && cost <= 31) {
                        return Strings.constantTimeAreEqual(bcryptString, doGenerate(version, password, decodeSaltString(bcryptString.substring(bcryptString.lastIndexOf(36) + 1, sLength - 31)), cost));
                    }
                    throw new IllegalArgumentException("Invalid cost factor: " + cost + ", 4 < cost < 31 expected.");
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid cost factor: " + costStr);
                }
            } else {
                throw new DataLengthException("Bcrypt String length: " + sLength + ", 60 required.");
            }
        }
    }

    private static String createBcryptString(String version, byte[] password, byte[] salt, int cost) {
        if (!allowedVersions.contains(version)) {
            throw new IllegalArgumentException("Version " + version + " is not accepted by this implementation.");
        }
        StringBuilder sb = new StringBuilder(60);
        sb.append('$');
        sb.append(version);
        sb.append('$');
        sb.append(cost < 10 ? "0" + cost : Integer.toString(cost));
        sb.append('$');
        encodeData(sb, salt);
        encodeData(sb, BCrypt.generate(password, salt, cost));
        return sb.toString();
    }

    private static void encodeData(StringBuilder sb, byte[] data) {
        if (data.length == 24 || data.length == 16) {
            boolean salt = false;
            if (data.length == 16) {
                salt = true;
                byte[] tmp = new byte[18];
                System.arraycopy(data, 0, tmp, 0, data.length);
                data = tmp;
            } else {
                data[data.length - 1] = 0;
            }
            int len = data.length;
            for (int i = 0; i < len; i += 3) {
                int a1 = data[i] & 255;
                int a2 = data[i + 1] & 255;
                int a3 = data[i + 2] & 255;
                sb.append((char) encodingTable[(a1 >>> 2) & 63]);
                sb.append((char) encodingTable[((a1 << 4) | (a2 >>> 4)) & 63]);
                sb.append((char) encodingTable[((a2 << 2) | (a3 >>> 6)) & 63]);
                sb.append((char) encodingTable[a3 & 63]);
            }
            if (salt) {
                sb.setLength(sb.length() - 2);
            } else {
                sb.setLength(sb.length() - 1);
            }
        } else {
            throw new DataLengthException("Invalid length: " + data.length + ", 24 for key or 16 for salt expected");
        }
    }

    private static byte[] decodeSaltString(String saltString) {
        char[] saltChars = saltString.toCharArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream(16);
        if (saltChars.length != 22) {
            throw new DataLengthException("Invalid base64 salt length: " + saltChars.length + " , 22 required.");
        }
        for (char c : saltChars) {
            if (c > 'z' || c < '.' || (c > '9' && c < 'A')) {
                throw new IllegalArgumentException("Salt string contains invalid character: " + ((int) c));
            }
        }
        char[] tmp = new char[24];
        System.arraycopy(saltChars, 0, tmp, 0, saltChars.length);
        int len = tmp.length;
        for (int i = 0; i < len; i += 4) {
            byte b1 = decodingTable[tmp[i]];
            byte b2 = decodingTable[tmp[i + 1]];
            byte b3 = decodingTable[tmp[i + 2]];
            byte b4 = decodingTable[tmp[i + 3]];
            out.write((b1 << 2) | (b2 >> 4));
            out.write((b2 << 4) | (b3 >> 2));
            out.write((b3 << 6) | b4);
        }
        byte[] tmpSalt = new byte[16];
        System.arraycopy(out.toByteArray(), 0, tmpSalt, 0, tmpSalt.length);
        return tmpSalt;
    }
}
