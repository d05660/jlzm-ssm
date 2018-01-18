package org.cloud.ssm.security;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.cloud.ssm.domain.User;
import org.cloud.ssm.service.IUserService;
import org.cloud.ssm.utils.TokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

public class JwtRealm extends AuthorizingRealm {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtRealm.class);

    @Autowired
    IUserService userService;

    @Override
    public boolean supports(AuthenticationToken token) {
        // 表示此Realm只支持JwtToken类型
        return token instanceof JwtToken;
    }

    /**
     * 
     * 只有当需要检测用户权限的时候才会调用此方法，例如checkRole,checkPermission之类的
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String)principals.getPrimaryPrincipal();
        // User user = userService.findByUsername(username);
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.setRoles(userService.findRoles(username));
        authorizationInfo.setStringPermissions(userService.findPermissions(username));
        return authorizationInfo;
    }

    /**
     * 默认使用此方法进行用户名正确与否验证，错误抛出异常即可。
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
            throws AuthenticationException {
        JwtToken jwtToken = (JwtToken) authenticationToken;
        // 获取token
        String token = jwtToken.getToken();

        // 从token中获取用户名
        String username = TokenUtil.getUsernameFromToken(token);

        // 根据用户名查询数据库
        User user = userService.findByUsername(username);
        if (user == null) {
            LOGGER.error("username or password error");
        }
        if (Boolean.TRUE.equals(user.getLocked())) {
            LOGGER.error("user locked");
            throw new LockedAccountException(); // 帐号锁定
        }
        try {
            return new SimpleAuthenticationInfo(username, token, getName());
        } catch (Exception e) {
            throw new AuthenticationException(e);
        }
    }

    @Override
    public void clearCachedAuthorizationInfo(PrincipalCollection principals) {
        super.clearCachedAuthorizationInfo(principals);
    }

    @Override
    public void clearCachedAuthenticationInfo(PrincipalCollection principals) {
        super.clearCachedAuthenticationInfo(principals);
    }

    @Override
    public void clearCache(PrincipalCollection principals) {
        super.clearCache(principals);
    }

    public void clearAllCachedAuthorizationInfo() {
        getAuthorizationCache().clear();
    }

    public void clearAllCachedAuthenticationInfo() {
        getAuthenticationCache().clear();
    }

    public void clearAllCache() {
        clearAllCachedAuthenticationInfo();
        clearAllCachedAuthorizationInfo();
    }
}
