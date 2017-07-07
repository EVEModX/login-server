# login-server 项目概述
此项目作为 EVEModX 的鉴权与授权模块

`/static` 存放所有的静态页面，可自行修改
`config.js` 为配置文件
## 启动说明

1. 安装 `node` 以及 `mysql` 软件
2. 配置 `config.js`
3. 运行 `node init.js` 默认用户 `root` 密码 `root`
4. 运行 `node app.js` 环境变量 `NODE_ENV` 必须加上 `production`

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
