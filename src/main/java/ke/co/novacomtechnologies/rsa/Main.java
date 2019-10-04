package ke.co.novacomtechnologies.rsa;

import com.fasterxml.jackson.databind.ObjectMapper;
import ke.co.novacomtechnologies.rsa.jackson.CallbackRequest;
import org.json.JSONObject;

import java.io.IOException;
import java.security.PublicKey;
import java.text.DecimalFormat;

public class Main
{
    private String callbackRequest = "{\"TransactionType\":\"CustomerPayBillValidation\",\"TransactionTime\":\"20191004115601\",\"TransactionID\":\"NJ45HBN8TH\",\"TransactionAmount\":10,\"BusinessShortcode\":\"107050\",\"AccountReference\":\"acc_ref\",\"SenderMSISDN\":\"254796778039\",\"SenderFirstName\":\"Peter\",\"SenderMiddleName\":null,\"SenderLastName\":\"Test\",\"RemainingCredits\":18,\"Signature\":\"1964fa1a35e5bd88d63e377a5c33f7b0ab328ac8394365ba2864ea46dfae1369b5bb2ee39e5c0eb6d0dc8ab2bbb921c3b1616beefa708325cda1e490f82d8e87c6ea6e242599bb0ca3b5d26fb77961721934182c64dd413a0c97b164aa721b17314ce3e542f82c1bce234e3d2cb41af7ffe22371063a00c4c57b7f47b181ac35\",\"PublicKey\":\"-----BEGIN RSA PUBLIC KEY-----\\r\\nMIGJAoGBAOS8Y8J5FGhSGAxMqfe4vWnHk7wL67IOFW2IvZTzSNx3rmP5HnxCNp5J\\r\\nykX6+JX0+CBthd9+A2eytzX9BtExfz5ziFcdMYFffxSYGGj2vNZmHL0WgxJIe+Yb\\r\\nN3EE+HLYpe0lmVyCABz1zzYsi\\/Rk1ON8qqxwVvpERBcLCsSzLWihAgMBAAE=\\r\\n-----END RSA PUBLIC KEY-----\"}";

    public static void main(String args[]) throws Exception
    {
        Main app = new Main();

        //if you want to use plain JSON objects...
        app.plainVerifier();

        //or using Jackson
        app.jacksonVerifier();
    }

    public boolean plainVerifier() throws Exception
    {
        JSONObject jsonObject = new JSONObject(callbackRequest);
        String pkJsonString = jsonObject.getString("PublicKey");
        String pkString = pkJsonString
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .trim();

        System.out.println(pkString);

        String amount = new DecimalFormat("0.##").format(jsonObject.getDouble("TransactionAmount"));
        String data = jsonObject.getString("TransactionID")
                + amount
                + jsonObject.getString("AccountReference")
                + jsonObject.getString("SenderMSISDN")
                + jsonObject.getString("BusinessShortcode");

        System.out.println("\nData: " + data);

        String signature = jsonObject.getString("Signature");

        Verifier verifier = new Verifier();
        PublicKey publicKey = verifier.getPublicKey(pkString);
        boolean verified = verifier.verify(publicKey, data, signature);

        System.out.println("\nVerified: " + (verified == true ? "True" : "False"));
        return verified;
    }

    public boolean jacksonVerifier() throws Exception
    {
        ObjectMapper objectMapper = new ObjectMapper();
        CallbackRequest request = objectMapper.readValue(callbackRequest, CallbackRequest.class);
        String pkJsonString = request.getPublicKey();
        String pkString = pkJsonString
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .trim();

        System.out.println(pkString);

        String amount = new DecimalFormat("0.##").format(request.getTransactionAmount());
        String data = request.getTransactionID()
                + amount
                + request.getAccountReference()
                + request.getSenderMSISDN()
                + request.getBusinessShortcode();

        System.out.println("\nData: " + data);

        String signature = request.getSignature();

        Verifier verifier = new Verifier();
        PublicKey publicKey = verifier.getPublicKey(pkString);
        boolean verified = verifier.verify(publicKey, data, signature);

        System.out.println("\nVerified: " + (verified == true ? "True" : "False"));
        return verified;
    }
}
