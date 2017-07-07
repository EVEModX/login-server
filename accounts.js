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
"use strict";
const debug=require('debug')('accounts');
const express=require('express');
const auth=require('./authentication');
const _=require('lodash');
const ds=require('./datasource');
const async=require('async');
let router=express.Router();
const mysql=require("mysql");
const config=require("./config");
let db=mysql.createConnection(config.mysql);
/*
* 权限系统：(accounts.*)
*   - accounts.add
*   - accounts.edit
*     |
*     +-accounts.give
*       |
*       +-accounts.getToken
*   - account.<account_id>.edit 仅由所有者拥有，包括删除
* */
/*
* 目前还是采用sql表存储
* */
const TABLE_NAME="eve_accounts";
const PRIV_TABLE_NAME="privileges";
/*
* 添加账号密码
* 授权验证:
*   - accounts.add
* 表单
*   :param token 用户token
*   :param account json编码的EVE账号信息 {username:<username>,password:<password>}
*   :param [account_owner=(token所指定的用户)] EVE账号所属ID
* 返回
*    成功返回200+账号ID
* */
function addaccount(req,resp){
    let eveacc=req.body.account,
        owner=req.body.account_owner,
        stopExec=false;
    debug('adding account:'+eveacc);
    try{
        eveacc=JSON.parse(eveacc);
    }catch(err){
        if (err instanceof SyntaxError){
            resp.status(400).end();
            stopExec=true;
        }
    }
    if (stopExec) return;
    debug('account parsed'+eveacc);
    if (_.isEmpty(eveacc)){
        debug('account is empty');
        resp.status(400).write(JSON.stringify({error:"missing arguments"}));
        resp.end();
        return;
    }
	let args=[req.body.account_owner || req.user.getID(),eveacc.username, eveacc.password];
	db.query("INSERT INTO "+TABLE_NAME+" (owner,username,password) VALUES (?,?,?)", args,function (err) {
            if (err) {resp.status(500).end();debug(err);return;}
            //TODO:处理UNIQUE冲突
            debug('account set, returning id');
            db.query("SELECT id FROM "+TABLE_NAME+" WHERE owner=? AND username=? AND password=?",args,function (err,row) {
                row=row[0];
                debug(row);
                if (err){resp.status(500).end();return;}
                resp.status(200).json({id:row.id});
                resp.end();
            });
        });
}
/*
* 修改账号
* 授权:
*   - accounts.edit.<account_id>
* 表单:
*   :param account_id EVE账号的ID
*	:param account 修改后的EVE账号
* */
function editaccount(req,resp){
    debug('editing account');
	let aid=req.body.account_id,
		eveacc=req.body.account,
        StopExec=false;
    if (!_.isNumber(aid) || !_.isFinite(aid) || !_.isString(eveacc)){
        resp.status(400).end();
        return;
    }
    try{
        eveacc=JSON.parse(eveacc);
    }catch(err){
        if (err instanceof SyntaxError){
            resp.status(400).write(JSON.stringify({error:"account format error"}));
            StopExec=true;
        }
    }
    debug('commit to database');
    if (StopExec) return;
    db.query("UPDATE "+TABLE_NAME+" SET username=?,password=? WHERE id=?",[eveacc.username,eveacc.password,aid],function (err){
        if (err) {resp.status(500).end();debug(err);return;}
        resp.status(200).end();
    });
}
/*
* 删除账号
* 表单:
*   :param account_id EVE账号的ID
* */
function deleteaccount(req,resp) {
    let aid=req.body.account_id;
    if (!_.isNumber(aid)){
        resp.status(400).end();
        return;
    }
    db.query("DELETE * FROM ? WHERE id=?",[TABLE_NAME,aid],function (err) {
        if (err) {resp.status(500).end();return;}
        ds.Authorize.delPermission("%","account:"+aid.toString(),"%",function (err) {
            if (err) {resp.status(500).end();return;}
            resp.status(200).end();
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
*   :param uri_type 1:国服 2:欧服
* 测试时直接回复用户名密码
* */
//TODO:实现国服/欧服
function requesttoken(req,resp){
	const aid=req.body.account_id;
	debug('requesting token of '+aid);
	if (!_.isNumber(aid) || !_.isFinite(aid)){
	    resp.status(400).end();
	    return;
    }
	const uri="https://auth.eve-online.com.cn/oauth/authorize?client_id=eveclient&scope=eveClientLogin&response_type=token&redirect_uri=https%3A%2F%2Fauth.eve-online.com.cn%2Flauncher%3Fclient_id%3Deveclient&lang=zh&mac=None";
	if (process.env.NODE_ENV === 'production'){

    }else {
	db.query("SELECT * FROM "+TABLE_NAME+" WHERE id=?",[aid],function (err,reply) {
	    reply=reply[0];
		if (err) {resp.status(500).end();debug('requesttoken err:'+JSON.stringify(err));return;}
		if (reply===undefined){
		    resp.status(404);
		    resp.end();
		    return;
        }
        reply.id=undefined;
		reply.owner=undefined;
		resp.status(200);
		resp.json(reply);
		resp.end();
    });
    }
}
/*
* 用户授权其他人使用EVE账号
* 授权:
*   - accounts.give.<account_id>
* 表单:
*   :param account_id 账户ID
*   :param give_to 被授予的用户ID
*   :param priv 授予的权限("gettoken":登录 "give":授予他人)
* */
function giveaccess(req,resp){
	let aid=req.body.account_id,
		given=req.body.give_to,
		priv=req.body.priv;
	debug('giving '+priv+' to uid:'+given+' on aid:'+aid);
	if (!_.isNumber(aid) || !_.isNumber(given) || (priv!=="getToken" && priv!=="give")){
        resp.status(400).end();
        return;
    }
    ds.User.findById(given,function (err,user) {
        if (err) {resp.status(500).end();return;}
        if (user===undefined){
            resp.status(404).end();
            return;
        }
        ds.Authorize.setPermission("user."+given,"account."+aid,priv,function (err) {
            if (err) {resp.status(500).end();return;}
            resp.status(200).end();
        });
    });
}
/*
* 撤销权限
* 表单:
*   :param account_id 账户ID
*   :param revoke_from 被撤销的用户ID
* */
function revokeaccess(req, resp) {
    let aid=req.body.account_id,
        revoke=req.body.revoke_from;
    if (!_.isNumber(aid) || !_.isNumber(revoke)){
        resp.status(400).end();
        return;
    }
    ds.User.findById(revoke,function (err,user) {
        if (err) {resp.status(500).end();return;}
        if (user===undefined){
            resp.status(404).end();
            return;
        }
        ds.Authorize.delPermission("user."+revoke,"account."+aid,"%",function (err) {
            if (err) {resp.status(500).end();return;}
            resp.status(200).end();
        });
    });
}
/*
* 获取某用户所有有权限的账户列表
* TODO：以后塞到存储过程去做
* 表单:
*   :param userid 用户ID
* 权限:
*   - users.view
* */
function get_accounts(req, resp) {
    let uid=req.body.userid;
    if (!_.isNumber(uid)){
        resp.status(400).end();
        return;
    }
    async.parallel([
        function (cb) {
            db.all("SELECT resource FROM ? WHERE role=?",[PRIV_TABLE_NAME,"user:"+uid.toString()],function (err,rows) {
                if (err) return cb(err);
                if (_.isEmpty(rows)) return cb(null,rows);
                return cb(null,rows.map(function (x) {
                    let t=x.resource.split('.');
                    return t.length===1?null:Number(t[1]);
                }));
            });
        },
        function (cb) {
            db.all("SELECT id FROM ? WHERE owner=?",[TABLE_NAME,uid],function (err,rows) {
                if (err) return cb(err);
                if (_.isEmpty(rows)) return cb(null,rows);
                return cb(null,rows.map(x => Number(x.id)));
            })
        }
    ],function (err,result) {
        if (err){resp.status(500).end();}
        let rt=new Set();
        for (let i=0,len=result.length;i<len;i++){
            rt.add(result[i]);
        }
        resp.status(200);
        resp.json(rt);
    });
}
/*
* 计算本模块所需要的权限
* @param role string 角色
* @param resource string 资源
* @param action string 动作
* @callback err:错误 result:授权结果 true/false
* */
function calcPermission(role,resource,action,callback) {
    debug("calcPerm: role->"+role+" resource->"+resource+" action->"+action);
    if (role==="user.1") return callback(null,true);
    let resultcb=function (err,results) {
        let ans=results.find(function (e) {
            return e.value==1;
        });
        return callback(null,ans!==undefined);
    };
    let defaultpriv=new Promise(function (resolve,reject) {
        let aid=Number(resource.split('.')[1]),
            uid=Number(role.split('.')[1]);
        if (isNaN(aid) || isNaN(uid)){
            reject({code:400});
            return;
        }
        db.query("SELECT owner FROM "+TABLE_NAME+" WHERE id= ?",[aid],function (err,result) {
            if (err){debug("default priv's err"+err);reject({code:500});return;}
            result=result[0];
            if (result.owner===uid) resolve();
            else reject({code:403});
        });
    });
    defaultpriv.then(function () {
        callback(null,true);
    }).catch(function (rejectmsg) {
        if (rejectmsg.code===500){
            callback(new Error("Error in calcPermission"));
            return;
        }
        switch (action){
            case "edit":
                async.parallel(async.reflectAll([
                    function (cb) {ds.Authorize.getPermission(role,resource,"edit",cb);},
                    function (cb) {ds.Authorize.getPermission(role,"accounts","edit",cb);}
                ]),resultcb);
                break;
            case "give":
                async.parallel(async.reflectAll([
                    function (cb) {ds.Authorize.getPermission(role,resource,"edit",cb);},
                    function (cb) {ds.Authorize.getPermission(role,resource,"give",cb);},
                    function (cb) {ds.Authorize.getPermission(role,"accounts","give",cb);},
                    function (cb) {ds.Authorize.getPermission(role,"accounts","edit",cb);}
                ]),resultcb);
                break;
            case "getToken":
                async.parallel(async.reflectAll([
                    function (cb) {ds.Authorize.getPermission(role,resource,"edit",cb);},
                    function (cb) {ds.Authorize.getPermission(role,resource,"give",cb);},
                    function (cb) {ds.Authorize.getPermission(role,resource,"getToken",cb);},
                    function (cb) {ds.Authorize.getPermission(role,"accounts","getToken",cb);},
                    function (cb) {ds.Authorize.getPermission(role,"accounts","give",cb);},
                    function (cb) {ds.Authorize.getPermission(role,"accounts","edit",cb);}
                ]),resultcb);
                break;
            case "add":
                callback(null,true);
                break;
            case "view":
                async.parallel(async.reflectAll([
                    function (cb) {ds.Authorize.getPermission(role,resource,"security_edit",cb);},
                    function (cb) {ds.Authorize.getPermission(role,resource,"edit",cb);},
                    function (cb) {ds.Authorize.getPermission(role,"users","security_edit",cb);},
                    function (cb) {ds.Authorize.getPermission(role,"users","edit",cb);}
                ]),resultcb);
                break;
            default:
                callback(null,false);
        }
    });
}
function authorization(req, resp, next){
	debug('authorize: '+req.path);
	let user=req.user,
		aid=req.body.account_id;
	async.series([
		function (cb) {
	        if (_.isEmpty(user)){
	            cb(null,{status:403});
            }else if (req.path==="/add"){
                cb(null);
            }else if (req.path==='/get_accounts'){
                calcPermission("user."+req.user.getID(),"user."+aid.toString(),"view",function (err,result) {
                    if (err) return cb(err);
                    else cb(null,result?undefined:{status:403});
                });
            }else if (!_.isNumber(aid) && _.isFinite(aid)){
                cb(null,{status:400,msg:"missing account id"});
            }else if (req.path==="/edit" || req.path==="/delete"){
                calcPermission("user."+req.user.getID(),"account."+aid.toString(),"edit",function (err,result) {
                    if (err) return cb(err);
                    else cb(null,result?undefined:{status:403});
                });
            }else if (req.path==="/give"){
                calcPermission("user."+req.user.getID(),"account."+aid.toString(),"give",function (err,result) {
                    if (err) return cb(err);
                    else cb(null,result?undefined:{status:403});
                })
            }else if (req.path==="/login"){
                calcPermission("user."+req.user.getID(),"account."+aid.toString(),"getToken",function (err,result) {
                    if (err) return cb(err);
                    else cb(null,result?undefined:{status:403});
                })
            }
        }
	],function (err,result) {
		"use strict";
		if (err) {debug('authorize 500 err:'+err);resp.status(500).end();return;}
		if (result!==undefined){
		    result=result[0];
        }
        if (result===undefined || result.status===undefined){
		    debug('authorize next');
		    next();
        }else{
            debug('authorize '+result.status+' msg:'+(result.msg===undefined?"N/A":result.msg));
            resp.status(result.status);
            if (result.msg!==undefined)
                resp.write(JSON.stringify({error:result.msg}));
            resp.end();
        }
    });
}
router.use(authorization);
router.post('/add',addaccount);
router.post('/edit',editaccount);
router.post('/get_accounts',get_accounts);
router.post('/delete',deleteaccount);
router.post('/login',requesttoken);
router.post('/revoke',revokeaccess);
router.post('/give',giveaccess);
module.exports=router;
/*
* */