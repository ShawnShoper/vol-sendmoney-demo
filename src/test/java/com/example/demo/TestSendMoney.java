package com.example.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.example.demo.vol.Convert;
import com.example.demo.vol.Crypto;
import okhttp3.*;
import org.junit.jupiter.api.Test;

import java.io.IOException;

public class TestSendMoney {

    @Test
    public void send() throws IOException {

        String publicKey = "2574eb56739de73b452cc98ea35798467c225b901651041b846335646e5a3533";
        String to = "VOL-MQZG-7RVP-A9MM-6HQDG";
        String passphrase = "";


        String unsigndTrxBytesHex = null;
        {
            OkHttpClient client = new OkHttpClient().newBuilder()
                    .build();
            MediaType mediaType = MediaType.parse("text/plain");
            RequestBody body = RequestBody.create(mediaType, "");
            Request request = new Request.Builder()
                    .url("http://47.52.42.90:9125/vol?requestType=sendMoney&recipient=" + to + "&deadline=180&feeNQT=10000000&amountNQT=100000000&message=Test&messageIsText=true&publicKey=" + publicKey)
                    .method("POST", body)
                    .build();
            Response response = client.newCall(request).execute();

            String responseString = response.body().string();
            JSONObject us = JSON.parseObject(responseString);
            unsigndTrxBytesHex = us.getString("unsignedTransactionBytes");


            response.close();
        }

        byte[] unsigndTrxBytes = Convert.parseHexString(unsigndTrxBytesHex);
        byte[] signature = Crypto.sign(unsigndTrxBytes, passphrase);
        byte[] signedTrxBytes = Crypto.signTransactionBytes(unsigndTrxBytes, signature);
        String signedTrxBytesHex = Convert.toHexString(signedTrxBytes);
        {
            OkHttpClient client = new OkHttpClient().newBuilder()
                    .build();
            MediaType mediaType = MediaType.parse("text/plain");
            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            RequestBody body = RequestBody.create(JSON, "{}");
            Request request = new Request.Builder()
                    .url("http://47.52.42.90:9125/vol?requestType=broadcastTransaction&transactionBytes=" + signedTrxBytesHex)
                    .method("POST", body)
                    .build();
            Response response = client.newCall(request).execute();
            String r = response.body().string();
            response.close();
        }


    }
}
