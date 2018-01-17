package org.cloud.ssm.service;

import java.util.List;
import java.util.Set;

import org.cloud.ssm.common.IBaseService;
import org.cloud.ssm.domain.User;

public interface IUserService extends IBaseService<User> {

    /**
     * 创建用户
     * @param user
     */
    public User createUser(User user);

    /**
     * 修改密码
     * @param userId
     * @param newPassword
     */
    public void changePassword(Long userId, String newPassword);

    /**
     * 添加用户-角色关系
     * @param userId
     * @param roleIds
     */
    public void correlationRoles(Long userId, Long... roleIds);


    /**
     * 移除用户-角色关系
     * @param userId
     * @param roleIds
     */
    public void uncorrelationRoles(Long userId, Long... roleIds);

    /**
     * 根据用户名查找用户
     * @param username
     * @return
     */
    public User findByUsername(String username);

    public Set<String> findRoles(String username);

    /**
     * 根据用户名查找其权限
     * @param username
     * @return
     */
    public Set<String> findPermissions(String username);
    
    public List<User> getAllUsers();
    
    public List<User> getPageUsers(int pagenum,int pagesize);
    
    public User updateUser(User u);
    
    public void deleteUser(Long userid);

    public User getUser(Long uid);
    
    public void deleteUserRoles(Long uid);

}
