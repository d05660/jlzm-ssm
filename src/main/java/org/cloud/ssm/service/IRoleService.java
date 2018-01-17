package org.cloud.ssm.service;

import java.util.List;

import org.cloud.ssm.common.IBaseService;
import org.cloud.ssm.domain.Role;

public interface IRoleService extends IBaseService<Role> {

    public Role createRole(Role role);
    public void deleteRole(Long roleId);

    /**
     * 添加角色-权限之间关系
     * @param roleId
     * @param permissionIds
     */
    public void correlationPermissions(Long roleId, Long... permissionIds);

    /**
     * 移除角色-权限之间关系
     * @param roleId
     * @param permissionIds
     */
    public void uncorrelationPermissions(Long roleId, Long... permissionIds);
    
    public List<Role> getRoles();
    
    public List<Role> getPageRole(int pagenum, int pagesize);
    
    public void deleteRoles(Long roleid);//删除该角色的所有权限关联
    
    public Role getRoleById(Long roleid);
    
    public Role updateRole(Role r);

}
