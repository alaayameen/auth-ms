package com.social.auth.services.models;

public class AppleIDTokenPayload {

    private String iss;
    private String aud;
    private Long exp;
    private Long iat;
    private String sub;// users unique id
    private String at_hash;
    private Long auth_time;
    private Boolean nonce_supported;
    private Boolean email_verified;
    private String email;

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getAt_hash() {
        return at_hash;
    }

    public void setAt_hash(String at_hash) {
        this.at_hash = at_hash;
    }

    public Long getAuth_time() {
        return auth_time;
    }

    public void setAuth_time(Long auth_time) {
        this.auth_time = auth_time;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((at_hash == null) ? 0 : at_hash.hashCode());
        result = prime * result + ((aud == null) ? 0 : aud.hashCode());
        result = prime * result + ((auth_time == null) ? 0 : auth_time.hashCode());
        result = prime * result + ((exp == null) ? 0 : exp.hashCode());
        result = prime * result + ((iat == null) ? 0 : iat.hashCode());
        result = prime * result + ((iss == null) ? 0 : iss.hashCode());
        result = prime * result + ((sub == null) ? 0 : sub.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AppleIDTokenPayload other = (AppleIDTokenPayload) obj;
        if (at_hash == null) {
            if (other.at_hash != null)
                return false;
        } else if (!at_hash.equals(other.at_hash))
            return false;
        if (aud == null) {
            if (other.aud != null)
                return false;
        } else if (!aud.equals(other.aud))
            return false;
        if (auth_time == null) {
            if (other.auth_time != null)
                return false;
        } else if (!auth_time.equals(other.auth_time))
            return false;
        if (exp == null) {
            if (other.exp != null)
                return false;
        } else if (!exp.equals(other.exp))
            return false;
        if (iat == null) {
            if (other.iat != null)
                return false;
        } else if (!iat.equals(other.iat))
            return false;
        if (iss == null) {
            if (other.iss != null)
                return false;
        } else if (!iss.equals(other.iss))
            return false;
        if (sub == null) {
            if (other.sub != null)
                return false;
        } else if (!sub.equals(other.sub))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "AppleIDTokenPayload [at_hash=" + at_hash + ", aud=" + aud + ", auth_time=" + auth_time + ", email="
                + email + ", email_verified=" + email_verified + ", exp=" + exp + ", iat=" + iat + ", iss=" + iss
                + ", nonce_supported=" + nonce_supported + ", sub=" + sub + "]";
    }

    public Boolean getNonce_supported() {
        return nonce_supported;
    }

    public void setNonce_supported(Boolean nonce_supported) {
        this.nonce_supported = nonce_supported;
    }

    public Boolean getEmail_verified() {
        return email_verified;
    }

    public void setEmail_verified(Boolean email_verified) {
        this.email_verified = email_verified;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}