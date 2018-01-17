package org.cloud.ssm.domain;

import java.util.List;

public class Permission {
    private Long id;
    private String permission;
    private String description;
    private List<RolePermission> rolePermission;
    
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getPermission() {
        return permission;
    }
    public void setPermission(String permission) {
        this.permission = permission;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public List<RolePermission> getRolePermission() {
        return rolePermission;
    }
    public void setRolePermission(List<RolePermission> rolePermission) {
        this.rolePermission = rolePermission;
    }
}
