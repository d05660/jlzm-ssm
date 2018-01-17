package org.cloud.ssm.service;

import java.util.List;

import org.cloud.ssm.domain.Permission;

public interface IPermissionService {
    
    public Long createPermission(Permission permission);

    public void deletePermission(Long permissionId);

    public void deletePermissions(Long permissionId);

    public List<Permission> getPermissions();

    public Permission getPermissionById(Long permissionid);

    public Permission updatePermission(Permission permission);

    public List<Permission> getPagePermissions(int pagenum, int pagesize);
}
