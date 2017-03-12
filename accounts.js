/**
 * Created by hanyuwei70 on 2017/2/20.
 */
/*
* 处理用户保存的用户名和密码，获取token返回
* 自行处理数据链接，不接入系统的数据接口
* */
/*
* 后续开发方向：在服务器被入侵时争取一部分时间给用户更改密码
* 密码处理部分交给后端Rust/Go解决
* 每个用户都有一个私钥对，存放在服务器上，私钥用客户密码hash加密
* A用户授权B用户使用账号X时，用A的密码解锁私钥，私钥解锁账户密码，然后用B的公钥加密存入
* */
var express=require('express');
var auth=require('./authentication');
var sqlite3=require('sqlite3');
var ds=require('./datasource');
var redis=require('redis'),
	rdsclient=redis.createClient();
var router=express.Router();
var db=new sqlite3.Database(__dirname+"/accounts.sqlite3").once('error',function (err) {
    console.error('error on opening '+__dirname+"/accounts.sqlite3");
});
/*
* 权限系统：(accounts.*)
*   - accounts.add
*   - accounts.edit.<account_id> 仅由所有者拥有，包括删除
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
        owner=req.body.account_owner,
        token=req.body.token;
    if (eveacc===undefined || owner===undefined || token===undefined){
        resp.status(500).write(JSON.stringify({error:"missing arguments"}));
        resp.end();
        return;
    }
    eveacc=JSON.parse(eveacc);
    ds.User.findByToken(token,function (err,user) {
        if (err){
            resp.status(500).write(JSON.stringify({error:"user not found"}));
            resp.end();
            return;
        }
        auth.querynode(user.getID(),"accounts.add",function(err,result){
			if (err){
				resp.status(500).write(JSON.stringify({error:"privilege error, please contact admin."}));
				resp.end();
				return;
			}
			if (result){
			    var newaccount={};
                newaccount.username=eveacc.username;
                newaccount.password=eveacc.password;
                newaccount.owner=user.getID();
                rdsclient.get("account_cnt",function(err,reply){
                	if (err){
                		resp.status(500).write(JSON.stringify({error:"Internal Error"}));
                		return;
					}
					if (reply===null) {
						rdsclient.set("account_cnt",1);
						reply=1;
                	}
					rdsclient.incr("account_cnt");
                	newaccount.id=reply;
				});
				rdsclient.set(newaccount.username,JSON.stringify(newaccount)); //TODO: hmset or json string? WARN:key必须改名字
                auth.addnode("accounts.edit."+newaccount.id.toString(),user.getID(),function (err,result) {
					if (err){resp.status(500).write(JSON.stringify({error:"Internal Server Error"}));return;}
					resp.status(200);
					resp.write(JSON.stringify({accountid:newaccount.id}));
					resp.end();
                });
			}
		});
    });
}
/*
* 修改/删除账号密码
* 授权:
*   - accounts.edit.<account_id>
* 表单:
*   :param token 用户token
*   :param account_id EVE账号的ID
*   :param action 操作 1:删除 2:修改
*	:param account 修改后的EVE账号
* */
var DELETE_ACCOUNT=1,EDIT_ACCOUNT=2;
function editaccount(req,resp){
	var token=req.body.token,
        aid=req.body.account_id,
		action=req.body.action,
		eveacc=req.body.eveaccount;
	ds.User.findByToken(token,function(err,user){
		if (err){resp.status(500).write(JSON.stringify({error:"Server Internal Error"})).end();return;}
		if (user===undefined) {
            resp.status(404).write(JSON.stringify({error: "user not found"}));
            return;
        }
		auth.querynode(user.getID(),"accounts.edit."+aid.toString(),function(err,reply){
			if (err) {resp.status(500).write(JSON.stringify({error:"Server Internal Error"})).end();return;}
			if (reply===0){
				resp.status(403).write(JSON.stringify({error:"not allowed"})).end();
				return;
			}
            var multi=rdsclient.multi();
			switch(action){
				case DELETE_ACCOUNT:
					multi.del("accounts.edit."+aid.toString());
					multi.del("accounts.give."+aid.toString());
					multi.del("accounts.gettoken."+aid.toString());
					break;
				case EDIT_ACCOUNT:
					multi.set(); //TODO:如何处理删除和修改
					break;
				default:
			}
		});
	});
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
