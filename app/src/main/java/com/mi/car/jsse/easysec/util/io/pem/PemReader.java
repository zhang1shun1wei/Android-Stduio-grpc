package com.mi.car.jsse.easysec.util.io.pem;

import com.mi.car.jsse.easysec.util.encoders.Base64;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

public class PemReader extends BufferedReader {
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";

    public PemReader(Reader reader) {
        super(reader);
    }

    public PemObject readPemObject() throws IOException {
        String line;
        int index;
        String line2 = readLine();
        while (line2 != null && !line2.startsWith(BEGIN)) {
            line2 = readLine();
        }
        if (line2 == null || (index = (line = line2.substring(BEGIN.length())).indexOf(45)) <= 0 || !line.endsWith("-----") || line.length() - index != 5) {
            return null;
        }
        return loadObject(line.substring(0, index));
    }

    private PemObject loadObject(String type) throws IOException {
        String line;
        String endMarker = END + type;
        StringBuffer buf = new StringBuffer();
        List headers = new ArrayList();
        while (true) {
            line = readLine();
            if (line == null) {
                break;
            }
            int index = line.indexOf(58);
            if (index >= 0) {
                headers.add(new PemHeader(line.substring(0, index), line.substring(index + 1).trim()));
            } else if (line.indexOf(endMarker) != -1) {
                break;
            } else {
                buf.append(line.trim());
            }
        }
        if (line != null) {
            return new PemObject(type, headers, Base64.decode(buf.toString()));
        }
        throw new IOException(endMarker + " not found");
    }
}
