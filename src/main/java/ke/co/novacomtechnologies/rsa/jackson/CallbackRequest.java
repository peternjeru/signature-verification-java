package ke.co.novacomtechnologies.rsa.jackson;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class CallbackRequest
{
    @JsonProperty("TransactionType")
    private String TransactionType;

    @JsonProperty("TransactionTime")
    private String TransactionTime;

    @JsonProperty("TransactionID")
    private String TransactionID;

    @JsonProperty("TransactionAmount")
    private Double TransactionAmount;

    @JsonProperty("BusinessShortcode")
    private String BusinessShortcode;

    @JsonProperty("AccountReference")
    private String AccountReference;

    @JsonProperty("SenderMSISDN")
    private String SenderMSISDN;

    @JsonProperty("SenderFirstName")
    private String SenderFirstName;

    @JsonProperty("SenderMiddleName")
    private String SenderMiddleName;

    @JsonProperty("SenderLastName")
    private String SenderLastName;

    @JsonProperty("RemainingCredits")
    private String RemainingCredits;

    @JsonProperty("Signature")
    private String Signature;

    @JsonProperty("PublicKey")
    private String PublicKey;
}
