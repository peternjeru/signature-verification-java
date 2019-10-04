package ke.co.novacomtechnologies.rsa;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.util.encoders.Base64;
import javax.xml.bind.DatatypeConverter;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;

public class Verifier
{
    public PublicKey getPublicKey(String keyString) throws Exception
    {
        byte keyBytes[] = Base64.decode(keyString);

        RSAPublicKey rsaPk = RSAPublicKey.getInstance(keyBytes);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(rsaPk.getModulus(), rsaPk.getPublicExponent());

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pk = kf.generatePublic(keySpec);
        return pk;
    }

    public boolean verify(PublicKey pk, String data, String signature) throws Exception
    {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(pk);
        sig.update(data.getBytes("UTF-8"));
        return sig.verify(DatatypeConverter.parseHexBinary(signature));
    }
}
