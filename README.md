# login-server 项目概述
此项目作为 EVEModX 的鉴权与授权模块

`/static` 存放所有的静态页面，可自行修改
`config.js` 为配置文件

## 通用模块

* `authentication.js` 用户凭证处理
* `datasource.js` 数据源模块/接口

##项目模块

* `accounts.js` 处理EVE帐号登录
* `userinfo.js` 用户个人信息填写

## 测试文件

* `test/main.js` 本模块用户管理
* `test/accounts.js` `accounts`模块
* `test/userinfo.js` `userinfo`模块