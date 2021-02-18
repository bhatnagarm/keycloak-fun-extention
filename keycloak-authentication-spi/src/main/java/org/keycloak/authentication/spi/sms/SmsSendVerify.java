package org.keycloak.authentication.spi.sms;

import com.twilio.Twilio;
import com.twilio.rest.verify.v2.service.Verification;
import com.twilio.rest.verify.v2.service.VerificationCheck;
import org.jboss.logging.Logger;

public class SmsSendVerify {

    private static final Logger log = Logger.getLogger(SmsSendVerify.class.getPackage().getName());

    private final transient String accountSid;
    private final transient String authToken;
    private final transient String serviceSid;
    private final transient OneTimePassword oneTimePassword = new OneTimePassword();


    public SmsSendVerify(final String accountSid, final String authToken, final String serviceSid) {
        this.accountSid = accountSid;
        this.authToken = authToken;
        this.serviceSid = serviceSid;
    }

    /* Use for sending OTP to the correct number. */
    public OneTimePassword sendOtp(String telNum) {
        oneTimePassword.setSid( serviceSid );
        log.info("Sending OTP to user :" + telNum);
        Twilio.init(accountSid, authToken);
        Verification verification = Verification.creator(
                oneTimePassword.getSid(),
                telNum,
                "sms")
                .create();

        oneTimePassword.setSuccessFlag("pending".equalsIgnoreCase(verification.getStatus()));
        return oneTimePassword;
    }


    /* Once client get the token they can put the
     * token here and it will verify.
     */
    public boolean receivePin(String telNum, String pin) {
        Twilio.init(accountSid, authToken);
        log.info("Received Mobile Number for the user is : " + telNum + " & recieved");
        VerificationCheck verificationCheck = VerificationCheck.creator(
                oneTimePassword.getSid(),
                pin)
                .setTo(telNum)
                .create();

        return "approved".equalsIgnoreCase(verificationCheck.getStatus());
    }

}
