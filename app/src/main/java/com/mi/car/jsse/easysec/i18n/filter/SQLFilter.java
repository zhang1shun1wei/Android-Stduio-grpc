package com.mi.car.jsse.easysec.i18n.filter;

public class SQLFilter implements Filter {
    @Override // com.mi.car.jsse.easysec.i18n.filter.Filter
    public String doFilter(String input) {
        StringBuffer buf = new StringBuffer(input);
        int i = 0;
        while (i < buf.length()) {
            switch (buf.charAt(i)) {
                case '\n':
                    buf.replace(i, i + 1, "\\n");
                    i++;
                    break;
                case '\r':
                    buf.replace(i, i + 1, "\\r");
                    i++;
                    break;
                case '\"':
                    buf.replace(i, i + 1, "\\\"");
                    i++;
                    break;
                case '\'':
                    buf.replace(i, i + 1, "\\'");
                    i++;
                    break;
                case '-':
                    buf.replace(i, i + 1, "\\-");
                    i++;
                    break;
                case '/':
                    buf.replace(i, i + 1, "\\/");
                    i++;
                    break;
                case ';':
                    buf.replace(i, i + 1, "\\;");
                    i++;
                    break;
                case '=':
                    buf.replace(i, i + 1, "\\=");
                    i++;
                    break;
                case '\\':
                    buf.replace(i, i + 1, "\\\\");
                    i++;
                    break;
            }
            i++;
        }
        return buf.toString();
    }

    @Override // com.mi.car.jsse.easysec.i18n.filter.Filter
    public String doFilterUrl(String input) {
        return doFilter(input);
    }
}
