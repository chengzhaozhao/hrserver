package org.sang.config;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Iterator;

/**
 * Created by sang on 2017/12/28.
 */
@Component
public class UrlAccessDecisionManager implements AccessDecisionManager {
    /**
     *
     * @param auth 用户角色信息
     * @param o
     * @param cas UrlFilterInvocationSecurityMetadataSource中的getAttributes方法传来的，表示当前请求需要的角色（可能有多个）。
     */
    @Override
    public void decide(Authentication auth, Object o, Collection<ConfigAttribute> cas){
        Iterator<ConfigAttribute> iterator = cas.iterator();
        while (iterator.hasNext()) {
            ConfigAttribute ca = iterator.next();
            //当前请求需要的权限
            String needRole = ca.getAttribute();
            //如果当前请求需要的权限为ROLE_LOGIN则表示登录即可访问，和角色没有关系，此时我需要判断authentication是不是AnonymousAuthenticationToken的一个实例，如果是，则表示当前用户没有登录，没有登录就抛一个BadCredentialsException异常，登录了就直接返回，则这个请求将被成功执行。
            if ("ROLE_LOGIN".equals(needRole)) {
                if (auth instanceof AnonymousAuthenticationToken) {
                    throw new BadCredentialsException("未登录");
                } else
                    return;
            }
            //当前用户所具有的权限
            Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
            for (GrantedAuthority authority : authorities) {
                //这里涉及到一个all和any的问题：假设当前用户具备角色A、角色B，当前请求需要角色B、角色C，那么是要当前用户要包含所有请求角色才算授权成功还是只要包含一个就算授权成功？我这里采用了第二种方案，即只要包含一个即可。小伙伴可根据自己的实际情况调整decide方法中的逻辑。
                if (authority.getAuthority().equals(needRole)) {
                    return;
                }
            }
        }
        //遍历collection，同时查看当前用户的角色列表中是否具备需要的权限，如果具备就直接返回，否则就抛异常
        throw new AccessDeniedException("权限不足!");
    }
    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }
    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}