# SpringSecurity学习

## JWT(JSON Web Token)实现:key:

- [x] 服务器给客户端签发`token`和`refresh_token`
- [x]  对客户端的访问进行鉴权
- [x] 当token过期之后，用户可以携带`refresh_token`访问`/api/refresh_token`来获得新的token
- [ ] 重构代码
- [ ] 编写测试

>token的过期时间目前设置为1min，refresh_token的过期时间为30min