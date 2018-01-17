package org.cloud.ssm.domain;

import java.util.List;

public class Role {
    private Long id;
    private String role;
    private String description;
    private List<UserRole> userRoles;  
    private List<RolePermission> rolePermissions;
   
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getRole() {
        return role;
    }
    public void setRole(String role) {
        this.role = role;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public List<UserRole> getUserRoles() {
        return userRoles;
    }
    public void setUserRoles(List<UserRole> userRoles) {
        this.userRoles = userRoles;
    }
    public List<RolePermission> getRolePermissions() {
        return rolePermissions;
    }
    public void setRolePermissions(List<RolePermission> rolePermissions) {
        this.rolePermissions = rolePermissions;
    }
}
