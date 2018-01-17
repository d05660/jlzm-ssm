package org.cloud.ssm.domain;

public class RolePermission {
    private Role role;
    private Permission permission;
    
    public Role getRole() {
        return role;
    }
    public void setRole(Role role) {
        this.role = role;
    }
    public Permission getPermission() {
        return permission;
    }
    public void setPermission(Permission permission) {
        this.permission = permission;
    }
}
