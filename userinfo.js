/**
 * Created by byr on 2016/12/5.
 */
/*
 * 用户信息处理模块
 * */
"use strict";
const express = require("express");
const data = require("./datasource");
const config = require("./config");
const debug = require('debug')('userinfo');
const _ = require("lodash");
let router = express.Router();
const mysql=require("mysql");
let db = mysql.createConnection(config.mysql);
const TABLE_NAME = "userinfo"; //数据表名
/*
 * 表结构
 * CREATE TABLE userinfo(
 *   id INTEGER NOT NULL PRIMARY KEY ON CONFLICT REPLACE,
 *   data TEXT
 * )
 * */

function getUserinfo_mysql(userid) {
    return new Promise((resolve, reject) => {
        db.query("SELECT * FROM " + TABLE_NAME + " WHERE id= ?", [userid], function (err, row) {
            if (err) reject({status: 500, msg: "Error in database"});
            row=row[0];
            if (row === undefined) reject({status: 404});
            try {
                row = JSON.parse(row.data);
            } catch (e) {
                if (e instanceof SyntaxError)
                    reject({status: 500, msg: "database corrupt"});
            }
            resolve(row);
        });
    });
}
/*
 * 获取用户信息
 * 表单:
 *   :param userid int 所请求的用户ID（默认为自己）
 *   :param info_req string 所请求的信息 (e.g. "{email:'',username:''}")
 * */
function getUserinfo(req, resp) {
    let p = new Promise((resolve, reject) => {
        let uid = req.body.userid || req.user.getID(),
            info_req = req.body.info_req;
        if (!_.isNumber(uid) || !_.isFinite(uid))
            reject({status: 400, msg: "missing uid"});
        try {
            info_req = JSON.parse(info_req);
        } catch (e) {
            if (e instanceof SyntaxError)
                reject({status: 400, msg: "missing info_req"});
        }
        resolve({uid: uid, info_req: info_req});
    });
    p.then(data => getUserinfo_mysql(data.uid)
        .then(row => {
            resp.status(200);
            let result = {};
            for (let key in data.info_req) {
                if (data.info_req.hasOwnProperty(key))
                    result[key] = row[key];
            }
            resp.json(result);
            resp.end();
        })
    ).catch(function (err) {
        debug(err);
        resp.status(err.status || 500);
        resp.write(err.msg || "unknown error");
        resp.end();
    });
}
function setUserinfo_mysql(userid, userinfo) {
    return new Promise((resolve, reject) => {
        db.query("INSERT INTO " + TABLE_NAME + " (id,data) VALUES(?,?)", [userid, userinfo], function (err) {
            if (err) reject({status: 500, msg: "database error"});
            else resolve();
        });
    });
}
/*设置用户信息
 * 表单：
 *   :param token string 授权token (默认转为req.user)
 *   :param info_req string 设置的信息 json编码
 *   :param [userid] int 要设置的用户ID 默认为req.user的ID
 * */
function setUserinfo(req, resp) {
    let p = new Promise((resolve, reject) => {
        let uid = req.body.userid,
            info = req.body.info_req;
        if (!uid) uid = req.user.data.userid;
        if (!_.isNumber(uid) || !_.isFinite(uid))
            reject({status: 400, msg: "missing uid"});
        try {
            JSON.parse(info);
        } catch (e) {
            if (e instanceof SyntaxError)
                reject({status: 400, msg: "missing info_req"});
            else
                reject({status: 500, msg:"unknown error"});
        }
        resolve({uid: uid, info: info});
    });
    p.then(data => setUserinfo_mysql(data.uid, data.info)
        .then(() => {
            resp.status(200);
            resp.end();
            debug('setUserinfo 200');
        }).catch((err)=>{
            resp.status(err.status||500);
            resp.write(err.msg || "unknown err at setUserinfo");
            resp.end();
        })
    ).catch((err)=>{
        resp.status(err.status || 500);
        resp.write(err.msg || "unknown error at setUserinfo");
        resp.end();
    });
}
function authorziation(req, resp, next) {
    if (req.path === '/setinfo') {
        if (req.user.getID() === 0 || !req.body.userid || req.user.data.userid === req.body.userid) {
            debug("auth next");
            next();
        } else {
            debug("auth 403");
            resp.status(403).end();
        }
    }
    else {
        debug("auth next");
        next();
    }
}
router.use(authorziation);
router.post('/getinfo', getUserinfo);
router.post('/setinfo', setUserinfo);
module.exports = router;