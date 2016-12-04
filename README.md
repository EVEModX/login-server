# Simplepage 项目概述

用于 nodejs 的学习以及为其它低CPU、高并发需求的网站搭建的模子

使用 [express](http://expressjs.com/) 作为框架，试验前后端分离以及REST API

页面全部采用 AJAX 来渲染，后端采用无状态设计

`/static` 存放所有的静态页面，可自行修改
`config.js` 为配置文件

## 通用模块

* `authentication.js` 鉴权模块
* `datasource.js` 数据源模块/接口
