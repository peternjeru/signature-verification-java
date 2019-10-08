package ke.co.novacomtechnologies.rsa;

import com.fasterxml.jackson.databind.ObjectMapper;
import ke.co.novacomtechnologies.rsa.jackson.CallbackRequest;
import org.json.JSONObject;
import java.security.PublicKey;
import java.text.DecimalFormat;

public class Main
{
    private String callbackRequest = "{\"TransactionType\":\"CustomerPayBillConfirmation\"," +
            "\"TransactionTime\":\"20191008083205\"," +
            "\"TransactionID\":\"NJ83HBNKED\"," +
            "\"TransactionAmount\":10," +
            "\"BusinessShortcode\":\"107050\"," +
            "\"AccountReference\":\"acc_ref\"," +
            "\"SenderMSISDN\":\"254796778039\"," +
            "\"SenderFirstName\":\"Peter\"," +
            "\"SenderMiddleName\":null," +
            "\"SenderLastName\":\"Test\"," +
            "\"RemainingCredits\":982," +
            "\"Signature\":\"I8iVcPXe5\\/KGyUUPwTj9AIymbSTp39hMaFJCW56ZuJK2QHNbh2zJVzynDZnB2sWI6pPb8GQR0s+FmhKow3gFwE2XaQ1JprX3jtVKEkW1UDwfw9XpXwlaBRLp6K+DLc7NPSxoeq5bj0Z9PjnLUTm0uklgA\\/HJS8HxI0O2gRIJZqY=\"," +
            "\"PublicKey\":\"-----BEGIN RSA PUBLIC KEY-----\\r\\nMIGJAoGBAJ6bBYcQrVNJH+dFvA1nkRXcuGrJLqKKuF7IscD6dvymi3xQht\\/bPC\\/z\\r\\nSXnu0RLQwvymyRsqgAs4+jDgZH5NRNIx8qg\\/8K\\/thNc+XJzssmt8gFddWR4V++Sf\\r\\nu8x8GPNtkJyGSywp4Y4yukt\\/CN7b2aop68bnhrZd8f\\/s8VJqR7EvAgMBAAE=\\r\\n-----END RSA PUBLIC KEY-----\"}";

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
        System.out.println("\n***Verify by plain JSON Objects***\n");
        JSONObject jsonObject = new JSONObject(callbackRequest);
        String pkJsonString = jsonObject.getString("PublicKey");
        String pkString = pkJsonString
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .trim();

        String amount = new DecimalFormat("0.##").format(jsonObject.getDouble("TransactionAmount"));
        String data = jsonObject.getString("TransactionTime")
                + jsonObject.getString("TransactionID")
                + amount
                + jsonObject.getString("AccountReference")
                + jsonObject.getString("SenderMSISDN")
                + jsonObject.getString("BusinessShortcode");

        String signature = jsonObject.getString("Signature");
        Verifier verifier = new Verifier();
        PublicKey publicKey = verifier.getPublicKey(pkString);
        boolean verified = verifier.verify(publicKey, data, signature);

        System.out.println("Verified: " + (verified == true ? "True" : "False"));
        return verified;
    }

    public boolean jacksonVerifier() throws Exception
    {
        System.out.println("\n***Verify by Jackson Pojo Objects***\n");
        ObjectMapper objectMapper = new ObjectMapper();
        CallbackRequest request = objectMapper.readValue(callbackRequest, CallbackRequest.class);
        String pkJsonString = request.getPublicKey();
        String pkString = pkJsonString
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .trim();

        String amount = new DecimalFormat("0.##").format(request.getTransactionAmount());
        String data = request.getTransactionTime()
                + request.getTransactionID()
                + amount
                + request.getAccountReference()
                + request.getSenderMSISDN()
                + request.getBusinessShortcode();
        String signature = request.getSignature();

        Verifier verifier = new Verifier();
        PublicKey publicKey = verifier.getPublicKey(pkString);
        boolean verified = verifier.verify(publicKey, data, signature);

        System.out.println("Verified: " + (verified == true ? "True" : "False"));
        return verified;
    }
}
