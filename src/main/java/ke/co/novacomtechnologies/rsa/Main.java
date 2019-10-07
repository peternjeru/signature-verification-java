package ke.co.novacomtechnologies.rsa;

import com.fasterxml.jackson.databind.ObjectMapper;
import ke.co.novacomtechnologies.rsa.jackson.CallbackRequest;
import org.json.JSONObject;
import java.security.PublicKey;
import java.text.DecimalFormat;

public class Main
{
    private String callbackRequest = "{\"TransactionType\":\"CustomerPayBillConfirmation\",\"TransactionTime\":\"20191007081144\",\"TransactionID\":\"NJ78HBNHAA\",\"TransactionAmount\":10,\"BusinessShortcode\":\"107050\",\"AccountReference\":\"acc_ref\",\"SenderMSISDN\":\"254796778039\",\"SenderFirstName\":\"Peter\",\"SenderMiddleName\":null,\"SenderLastName\":\"Test\",\"RemainingCredits\":983,\"Signature\":\"db0d88f2ae43ca244ae8650b151d94cbe40a540ae30df64ae5559cef7866961911b4e802205af561b569833c5bcf710fa9d3cd540d5432a8d31d5a1fc8d02b33b2cef345388d65b7fb26fc9509676ab73eb0d35042e55d5766e2818f35c56b535ce3c7e097417575d3788601d373b6f7cc401f093302a8fcd75becaa2f9cbac1\",\"PublicKey\":\"-----BEGIN RSA PUBLIC KEY-----\\r\\nMIGJAoGBAN4ZwWG3mRtJoBOw\\/z9+\\/\\/z\\/nM6IlFt1vpDeLM0i\\/swZqeV1Jzh8E0KP\\r\\neUHyIvrWJjxsFXI4kbCmhGm44baB4IRkWYc+M7eSWtWTKz12EY0MNdVCed1HqvAy\\r\\n4cNQ1FSEuqQt6Iroe5D8JF5V3+3Pg7IrfW2NVn\\/+BNVidYeyElnfAgMBAAE=\\r\\n-----END RSA PUBLIC KEY-----\"}";

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

        System.out.println(pkString);

        String amount = new DecimalFormat("0.##").format(jsonObject.getDouble("TransactionAmount"));
        String data = jsonObject.getString("TransactionTime")
                + jsonObject.getString("TransactionID")
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
        System.out.println("\n***Verify by Jackson Pojo Objects***\n");
        ObjectMapper objectMapper = new ObjectMapper();
        CallbackRequest request = objectMapper.readValue(callbackRequest, CallbackRequest.class);
        String pkJsonString = request.getPublicKey();
        String pkString = pkJsonString
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .trim();

        System.out.println(pkString);

        String amount = new DecimalFormat("0.##").format(request.getTransactionAmount());
        String data = request.getTransactionTime()
                + request.getTransactionID()
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
