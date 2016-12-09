# REST API 手册

## 登录相关

### `/login` 登录获取token

* `username` 用户名
* `password` 密码

返回值

* `token`:获取的token
* `expiretime`: 过期时间 Unix Timestamp格式

错误返回 403

### `/renew` 续期token

* `username` 用户名
* `token` 之前获取的token

返回值同 `/login`

### `/logout` 注销token

* `username` 用户名
* `token` 之前获取的token

返回值

* `msg` 附加信息

错误返回 403

##用户相关

### `/user/getinfo` 获取用户信息

* `username_req` / `userid_req` 请求的用户名/ID 只需要指定一个
* 附加身份验证信息

返回

* `userinfo` json编码用户信息

### `/user/setinfo` 设置用户信息

* `username_req` / `userid_req` 请求的用户名/ID 只需要指定一个
* `userinfo` json编码用户信息

返回

HTTP状态码

