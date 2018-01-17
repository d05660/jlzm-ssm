package org.cloud.ssm.security;

import org.apache.shiro.authc.AuthenticationToken;

public class JwtToken implements AuthenticationToken {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    
    private String principal;

    private String token;
    
    public JwtToken() {}

    public JwtToken(String principal, String token) {
        super();
        this.principal = principal;
        this.token = token;
    }
    
    public JwtToken(String token) {
        super();
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    @Override
    public String getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public String toString() {
        return "JwtToken [principal=" + principal + ", token=" + token + "]";
    }
}
