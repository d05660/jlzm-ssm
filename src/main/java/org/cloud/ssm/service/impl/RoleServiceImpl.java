package org.cloud.ssm.service.impl;

import java.util.List;
import java.util.Optional;

import javax.annotation.Resource;

import org.cloud.ssm.common.BaseServiceImpl;
import org.cloud.ssm.domain.Role;
import org.cloud.ssm.mapper.RoleMapper;
import org.cloud.ssm.service.IRoleService;
import org.springframework.stereotype.Service;

@Service
public class RoleServiceImpl extends BaseServiceImpl<RoleMapper, Role> implements IRoleService {
    
    @Resource
    RoleMapper roleMapper;

    @Override
    public Role createRole(Role role) {
        this.save(role);
        return role;
    }

    @Override
    public void deleteRole(Long roleId) {
        this.deleteById(roleId);
    }

    @Override
    public List<Role> getRoles() {
        return this.getAll();
    }

    @Override
    public Role getRoleById(Long roleid) {
        Optional<Role> optional = this.getById(roleid);
        return optional.orElse(null);
    }

    @Override
    public Role updateRole(Role r) {
        this.save(r);
        return r;
    }
    
    @Override
    public List<Role> getPageRole(int pagenum, int pagesize) {
        return this.getAll(pagenum, pagesize);
    }
    
    @Override
    public void correlationPermissions(Long roleId, Long... permissionIds) {
        for(Long pid:permissionIds){
            roleMapper.addRolePermission(roleId, pid);
        }
    }
    
    @Override
    public void uncorrelationPermissions(Long roleId, Long... permissionIds) {
        for(Long pid:permissionIds){
            roleMapper.deleteRolePermission(roleId, pid);
        }
    }

    @Override
    public void deleteRoles(Long roleid) {
        roleMapper.deleteRoles(roleid);
    }
}
