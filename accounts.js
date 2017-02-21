/**
 * Created by hanyuwei70 on 2017/2/20.
 */
/*
* 处理用户保存的用户名和密码，获取token返回
* */
/*
* 后续开发方向：在服务器被入侵时争取一部分时间给用户更改密码
* 密码处理部分交给后端Rust/Go解决
* 每个用户都有一个私钥对，存放在服务器上，私钥用客户密码hash加密
* A用户授权B用户使用账号X时，用A的密码解锁私钥，私钥解锁账户密码，然后用B的公钥加密存入
* */
var express=require('express');
var router=express.Router();

/*
* 权限系统：(accounts.*)
*   - accounts.add
*   - accounts.edit.<account_id> (仅由所有者拥有)
*     |
*     +-accounts.give.<account_id>
*       |
*       +-accounts.gettoken.<account_id>
* */


/*
* 添加账号密码
* 授权验证:
*   - accounts.add
* 表单
*   :param token 用户token
*   :param account json编码的EVE账号信息 {username:<username>,password:<password>}
*   :param account_owner EVE账号所属ID
* */
function addaccount(req,resp){
    var eveacc=req.body.account,
        owner=req.body.account_owner;

}
/*
* 修改/删除账号密码
* 授权:
*   - accounts.edit.<account_id>
* 表单:
*   :param token 用户token
*   :param account_id EVE账号的ID
* */
function editaccount(req,resp){

}
/*
* 向天成服务器请求EVE登录token
* 授权
*   - accounts.gettoken.<account_id>
* 表单
*   :param token 用户token
*   :param account_id 请求的EVE账号的ID
* */
function requesttoken(req,resp){

}
/*
* 用户授权其他人使用EVE账号
* 授权:
*   - accounts.give.<account_id>
* 表单:
*   :param token 用户token
*   :param account_id EVE账号的ID
*   :param give_to 被授予的用户ID
*   :param priv 授予的权限("gettoken":登录 "give":授予他人)
* */
function giveaccess(req,resp){

}
router.post('/add',addaccount);
router.post('/edit',editaccount);
router.post('/delete',editaccount);
router.post('/login',requesttoken);
router.post('/giveaccess',giveaccess);
module.exports=router;