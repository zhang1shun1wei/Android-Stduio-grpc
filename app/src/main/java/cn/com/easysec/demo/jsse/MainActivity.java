package cn.com.easysec.demo.jsse;

import android.os.Handler;
import android.os.Message;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.mi.car.jsse.easysec.JSSEUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;


public class MainActivity extends AppCompatActivity {


    private TextView resp;
    private String response = "";
    private static int BUFFERLENGTH = 1024;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        resp = findViewById(R.id.response);
        Button test = findViewById(R.id.test);
//        //子线程网络请求
//        String url = "https://pre-fileup-tsp.api.xiaomi.com/vehicle/file/create?businessType=1&collectTime=1663148277&fileName=test.log&fileSize=6&linkMode=1&packTime=1663148277&reportTime=1663148277&vin=abcdefgh";
//        String params = "{\"sourceEcu\": 1, \"appName\": \"testsdk\"}";
//        response = connection(url, params);
//        handler.sendEmptyMessage(0);
//        Log.e("response", response);
        test.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new Thread(() -> {
                    //子线程网络请求
                    String url = "https://pre-fileup-tsp.api.xiaomi.com/vehicle/file/create?businessType=1&collectTime=1663148277&fileName=test.log&fileSize=6&linkMode=1&packTime=1663148277&reportTime=1663148277&vin=abcdefgh";
                    String params = "{\"sourceEcu\": 1, \"appName\": \"testsdk\"}";
                    response = connection(url, params);
                    handler.sendEmptyMessage(0);
                    Log.e("response", response);

                }).start();
            }
        });
    }

    private Handler handler = new Handler() {
        @Override
        public void handleMessage(@NonNull Message msg) {
            if (msg.what == 0) {
                resp.setText(response);
            }
        }
    };


    private String connection(String serverURL, String params) {

        try {
            URL url = new URL(serverURL);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setConnectTimeout(60000);
            connection.setReadTimeout(60000);
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setSSLSocketFactory(JSSEUtil.makeSSLContext().getSocketFactory());
            //此为demo示例，可按实际需求校验hostname
            connection.setRequestProperty("Connection", "close");
            connection.setRequestProperty("User-Agent", "MIClient 1.0");
            connection.setRequestProperty("Accept-Charset", "UTF-8");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.connect();

            OutputStream outputStream = connection.getOutputStream();
//            outputStream.write(params.getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                //获得connection的输入流对象
                InputStream inputStream = connection.getInputStream();
                String response = parseSteam(inputStream);
                return response;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    private String parseSteam(InputStream inputStream) {
        try {
            ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[BUFFERLENGTH];
            int len = 0;
            while ((len = inputStream.read(buffer)) != -1) {
                arrayOutputStream.write(buffer, 0, len);
            }
            return arrayOutputStream.toString("utf-8");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
