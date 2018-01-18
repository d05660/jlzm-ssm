package org.cloud.ssm.controller;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.subject.Subject;
import org.cloud.ssm.common.ResponseMessage;
import org.cloud.ssm.domain.User;
import org.cloud.ssm.security.JwtToken;
import org.cloud.ssm.service.IUserService;
import org.cloud.ssm.utils.TokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mobile.device.Device;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginController.class);

    @Autowired
    IUserService userService;

    @PostMapping("/login")
    @ResponseBody
    public ResponseMessage login(@RequestBody User loginUser, HttpServletResponse response, Device device)
            throws IOException {
        String username = loginUser.getUsername();
        String password = loginUser.getPassword();

        // 验证用户名密码成功后生成token
        String token = TokenUtil.generateToken(username, device);

        // 构建JwtToken
        JwtToken jwtToken = new JwtToken(username, token);
        LOGGER.info(jwtToken.toString());
        Subject subject = SecurityUtils.getSubject();
        try {
            // 该方法会调用JwtRealm中的doGetAuthenticationInfo方法
            subject.login(jwtToken);
        } catch (UnknownAccountException exception) {
            LOGGER.error("账号不存在");
        } catch (IncorrectCredentialsException exception) {
            LOGGER.error("错误的凭证，用户名或密码不正确");
        } catch (LockedAccountException exception) {
            LOGGER.error("账户已锁定");
        } catch (ExcessiveAttemptsException exception) {
            LOGGER.error("错误次数过多");
        } catch (AuthenticationException exception) {
            // exception.printStackTrace();
            LOGGER.error("认证失败");
        }
        // 认证通过
        if (subject.isAuthenticated()) {
            // 将token写出到cookie
            Cookie cookie = new Cookie("token", token);
            cookie.setHttpOnly(true);
            cookie.setMaxAge(3600 * 5);
            cookie.setPath("/");
            response.addCookie(cookie);
            response.flushBuffer();
            return new ResponseMessage(200, "success", token);
        } else {
            return new ResponseMessage(403, "error");
        }
    }

    /**
     * 登出
     * 
     * @param request
     * @param response
     * @return
     * @throws IOException
     */
    @GetMapping(value = "/logout")
    public Object logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Optional<Cookie> cookie = Arrays.stream(request.getCookies()).filter(ck -> "token".equals(ck.getName()))
                .limit(1).map(ck -> {
                    ck.setMaxAge(0);
                    ck.setHttpOnly(true);
                    ck.setPath("/");
                    return ck;
                }).findFirst();
        response.addCookie(cookie.get());
        response.flushBuffer();
        return new ResponseMessage(200, "success");
    }

}
