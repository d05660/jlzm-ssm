package org.cloud.ssm.domain;

import java.util.List;

public class User {
    private Long id;
    private String username;
    private String password;
    private Boolean locked;
    private List<UserRole> userRoles;
    
    public User() {}
    
    public User(String username, String password) {
        super();
        this.username = username;
        this.password = password;
    }
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public Boolean getLocked() {
        return locked;
    }
    public void setLocked(Boolean locked) {
        this.locked = locked;
    }
    public List<UserRole> getUserRoles() {
        return userRoles;
    }
    public void setUserRoles(List<UserRole> userRoles) {
        this.userRoles = userRoles;
    }
}
