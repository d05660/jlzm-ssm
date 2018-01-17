package org.cloud.ssm.service.impl;

import java.util.List;
import java.util.Optional;

import javax.annotation.Resource;

import org.cloud.ssm.common.BaseServiceImpl;
import org.cloud.ssm.domain.Permission;
import org.cloud.ssm.mapper.PermissionMapper;
import org.cloud.ssm.service.IPermissionService;
import org.springframework.stereotype.Service;

@Service
public class PermissionServiceImpl extends BaseServiceImpl<PermissionMapper, Permission> 
    implements IPermissionService {

    @Resource
    PermissionMapper permissionMapper;

    @Override
    public Long createPermission(Permission permission) {
        return this.save(permission);
    }

    @Override
    public void deletePermission(Long permissionId) {
        this.deleteById(permissionId);
    }

    @Override
    public void deletePermissions(Long permissionId) {
        permissionMapper.deletePermissionsById(permissionId);
    }

    @Override
    public List<Permission> getPermissions() {
        return this.getAll();
    }

    @Override
    public Permission getPermissionById(Long permissionid) {
        Optional<Permission> optional = this.getById(permissionid);
        return optional.orElse(null);
    }

    @Override
    public Permission updatePermission(Permission permission) {
        this.save(permission);
        return permission;
    }

    @Override
    public List<Permission> getPagePermissions(int pagenum, int pagesize) {
        List<Permission> list = this.getAll(pagenum, pagesize);
        return list;
    }

}
