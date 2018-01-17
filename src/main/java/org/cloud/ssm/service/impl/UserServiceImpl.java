package org.cloud.ssm.service.impl;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.cloud.ssm.common.BaseServiceImpl;
import org.cloud.ssm.domain.Role;
import org.cloud.ssm.domain.RolePermission;
import org.cloud.ssm.domain.User;
import org.cloud.ssm.domain.UserRole;
import org.cloud.ssm.mapper.RoleMapper;
import org.cloud.ssm.mapper.UserMapper;
import org.cloud.ssm.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.github.pagehelper.PageHelper;

@Service
public class UserServiceImpl extends BaseServiceImpl<UserMapper, User> implements IUserService {

    @Autowired
    UserMapper userMapper;
    
    @Autowired
    RoleMapper roleMapper;

    @Override
    public User createUser(User user) {
        userMapper.insert(user);
        return user;
    }

    @Override
    public void changePassword(Long userId, String newPassword) {
        User u = userMapper.selectByPrimaryKey(userId);
        u.setPassword(newPassword);
        userMapper.updateByPrimaryKey(u);
    }

    @Override
    public void correlationRoles(Long userId, Long... roleIds) {
        for (Long roleid : roleIds) {
            userMapper.addUserRole(userId, roleid);
        }
    }

    @Override
    public void uncorrelationRoles(Long userId, Long... roleIds) {
        for (Long roleid : roleIds) {
            userMapper.deleteUserRole(userId, roleid);
        }
    }

    @Override
    public User findByUsername(String username) {
        return userMapper.selectUserByUsername(username);
    }

    @Override
    public Set<String> findRoles(String username) {
        Set<String> roles = new HashSet<>();
        User u = userMapper.selectUserByUsername(username);
        List<UserRole> user_roles = u.getUserRoles();
        for (UserRole ur : user_roles) {
            Role r = ur.getRole();
            roles.add(r.getRole());
        }
        return roles;
    }

    @Override
    public Set<String> findPermissions(String username) {
        Set<String> permissions = new HashSet<>();
        User u = userMapper.selectUserByUsername(username);
        List<UserRole> userRoles = u.getUserRoles();
        for (UserRole ur : userRoles) {
            Role role = roleMapper.selectByPrimaryKey(ur.getRole().getId());
            List<RolePermission> rps = role.getRolePermissions();
            for (RolePermission rp : rps) {
                String permission = rp.getPermission().getPermission();
                permissions.add(permission);
            }
        }
        return permissions;
    }

    @Override
    public List<User> getAllUsers() {
        return userMapper.selectAll();
    }

    @Override
    public List<User> getPageUsers(int pagenum, int pagesize) {
        PageHelper.startPage(pagenum, pagesize);
        List<User> users = userMapper.selectAll();
        return users;
    }

    @Override
    public User updateUser(User u) {
        userMapper.updateByPrimaryKey(u);
        return u;
    }

    @Override
    public void deleteUser(Long userid) {
        userMapper.deleteByPrimaryKey(userid);
    }

    @Override
    public User getUser(Long uid) {
        User u = userMapper.selectByPrimaryKey(uid);
        return u;
    }

    @Override
    public void deleteUserRoles(Long uid) {
        userMapper.deleteUserRoles(uid);
    }
}
