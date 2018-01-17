package org.cloud.ssm.mapper;

import org.cloud.ssm.common.BaseMapper;
import org.cloud.ssm.domain.User;

public interface UserMapper extends BaseMapper<User> {

    User selectUserByUsername(String username);

    void deleteUserRole(long userid, long roleid);

    void addUserRole(long userid, long roleid);

    void deleteUserRoles(long uid);
}
