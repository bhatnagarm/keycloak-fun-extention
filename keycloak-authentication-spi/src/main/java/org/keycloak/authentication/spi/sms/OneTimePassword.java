package org.keycloak.authentication.spi.sms;

public class OneTimePassword {

    private boolean successFlag;
    private String sid;

    public boolean isSuccessFlag() {
        return successFlag;
    }

    public void setSuccessFlag(boolean successFlag) {
        this.successFlag = successFlag;
    }

    public String getSid() {
        return sid;
    }

    public void setSid(String sid) {
        this.sid = sid;
    }

}
