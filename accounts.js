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
var async=require('async');
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
*       +-accounts.getToken.<account_id>
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
//TODO:数据一致性
function addaccount(req,resp){
    var eveacc=req.body.account,
        owner=req.body.account_owner;
    if (eveacc===undefined || owner===undefined){
        resp.status(400).write(JSON.stringify({error:"missing arguments"}));
        resp.end();
        return;
    }
	var newaccount={};
	newaccount.username=eveacc.username;
	newaccount.password=eveacc.password;
	newaccount.owner=user.getID();
	rdsclient.get("account_cnt",function(err,reply){
		if (err){
			resp.status(500).write().end();
			//TODO:日志
			return;
		}
		if (reply===null) {
			rdsclient.set("account_cnt",1);
			reply=1;
		}
		rdsclient.incr("account_cnt");
		newaccount.id=reply;
	});
	var multi=rdsclient.multi();
	multi.set(newaccount.id,JSON.stringify(newaccount));
	multi.sadd("user."+user.getID()+".accounts",newaccount.id);
	multi.exec(function (err,result) {
		if (err) {resp.status(500).end();return;}
        auth.addnode("accounts.edit."+newaccount.id.toString(),user.getID(),function (err,result) {
            if (err){resp.status(500).write(JSON.stringify({error:"Internal Server Error"}));return;}
            resp.status(200);
            resp.write(JSON.stringify({accountid:newaccount.id}));
            resp.end();
        });
    });
}
/*
* 修改/删除账号密码
* 授权:
*   - accounts.edit.<account_id>
* 表单:
*   :param account_id EVE账号的ID
*   :param action 操作 1:删除 2:修改
*	:param account 修改后的EVE账号
* */
var DELETE_ACCOUNT=1,EDIT_ACCOUNT=2;
function editaccount(req,resp){
	var aid=req.body.account_id,
		action=req.body.action,
		eveacc=req.body.account;
	var multi=rdsclient.multi();
	switch(action){
		case DELETE_ACCOUNT:
			async.series([
				function (callback) {
                    multi.del("accounts.edit."+aid.toString());
                    multi.del("accounts.give."+aid.toString());
                    multi.del("accounts.getToken."+aid.toString());
                    multi.del(aid);
                    callback();
                },
				function (callback) {
                    rdsclient.keys("user.*.accounts",function (err,replies) {
                        if (err) return callback(err);
                        replies.forEach(function (reply) {
                            multi.srem(reply,aid);
                        });
                    });
                    callback();
                },
				function (callback) {
					multi.exec(function (err,replies) {
						if (err) return callback(err);
						return callback();
                    })
                }
			],function (err,result) {
                if (err) {resp.status(500).end();return;}
                resp.status(200).end();
			});
			break;
		case EDIT_ACCOUNT:
			var newaccount={};
			newaccount.username=eveacc.username;
			newaccount.password=eveacc.password;
			newaccount.owner=req.user.getID();
			newaccount.id=aid;
			multi.set(aid,newaccount); //TODO:如何处理删除和修改
			multi.exec(function (err,reply) {
				if (err) {resp.status(500).end();return;}
				resp.status(200).end();
            });
			break;
		default:
			resp.status(400).end();
	}
}
/*
* 向天成服务器请求EVE登录token
* 授权
*   - accounts.gettoken.<account_id>
* 表单
*   :param token 用户token
*   :param account_id 请求的EVE账号的ID
* */
//TODO:实现
function requesttoken(req,resp){
	var aid=req.body.account_id;
	var uri="https://auth.eve-online.com.cn/oauth/authorize?client_id=eveclient&scope=eveClientLogin&response_type=token&redirect_uri=https%3A%2F%2Fauth.eve-online.com.cn%2Flauncher%3Fclient_id%3Deveclient&lang=zh&mac=None"
	rdsclient.get(aid,function (err,reply) {
		if (err) {resp.status(500).end();return;}
		resp.status(200).write(reply).end();
    })
}
/*
* 用户授权其他人使用EVE账号
* 授权:
*   - accounts.give.<account_id>
* 表单:
*   :param give_to 被授予的用户ID
*   :param priv 授予的权限("gettoken":登录 "give":授予他人)
* */
//TODO:撤销权限
function giveaccess(req,resp){
	var aid=req.body.account_id,
		given=req.body.give_to,
		priv=req.body.priv;
	ds.User.findById(given,function (err,user) {
		if (err) {resp.status(500).end();return;}
		if (!user){
			resp.status(404).write(JSON.stringify({error:"user not found"})).end();
			return;
		}
		auth.addnode(user.getID(),"accounts."+priv+"."+aid,function (err,result) {
			if (err || !result){resp.status(500).end();return;}
			resp.status(200).end();
        });
	});
}
function get_accounts(req, resp) {
	var user=req.user;
	rdsclient.smember("user."+user.getID()+".accounts",function (err,reply) {
		if (err) {resp.status(500).end();return;}
		resp.status(200).write(JSON.stringify(reply)).end();
    });
}
function authorization(req, resp, next){
	console.log(req.path);
	var user=req.user,
		aid=req.body.account_id;
	async.series([
		function (callback) {
			auth.querynode(user.getID(),"accounts.edit."+aid.toString(),function (err,reply) {
				if (err) return callback({error:err});
				if (reply===1) return callback({data:"edit"});
				callback();
            })
        },
		function (callback) {
			auth.querynode(user.getID(),"accounts.give."+aid.toString(),function (err,reply) {
				if (err) return callback({error:err});
				if (reply===1) return callback({data:"give"});
				callback();
            })
        },
		function (callback) {
			auth.querynode(user.getID(),"accounts.getToken."+aid.toString(),function (err,reply) {
				if (err) return callback({error:err});
				if (reply===1) return callback({data:"getToken"});
				callback();
            })
        }
	],function (result) {
		if (!result && req.path!="/add"){
			resp.status(403).end();
		}else if (result.error){
			resp.status(500).end();
		}else{
			var reject=function () {
				resp.status(403).end();
            };
			if (req.path==="/give" && result.data==="getToken"){
				reject();
            }else if (req.path==="/edit" && req.path==="/delete" && result.data==="give"){
				reject();
			}else{
            	next();
			}
		}
    });
}
router.use(authorization);
router.post('/add',addaccount);
router.post('/edit',editaccount);
router.post('/get_accounts',get_accounts);
router.post('/delete',editaccount);
router.post('/login',requesttoken);
router.post('/give',giveaccess);
module.exports=router;
