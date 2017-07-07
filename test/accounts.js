//encoding:utf-8
/*
* account模块测试集
* */
"use strict";
let app=require('../app');
const request=require('supertest')('http://localhost:8080');
const should=require('should');
const debug = require('debug')('test');
const mysql = require('mysql');
const async = require("async");
const config = require('../config');
describe('accounts module',function () {
    let tokens=[],uids=[];
    let roottoken;
    let users=[{username:"pibc",password:"pibc"},
               {username:"tga",password:"tga"},
               {username:"p1",password:"p2"},
               {username:"p2",password:"p2"},
               {username:"fbp",password:"fbp"},];
    let db=mysql.createConnection(config.mysql);
    let aid1=0;
    before('clear all accounts and privileges',function (done) {
        this.timeout(10000);
        async.series([
            function (cb) {
                debug('cleaning database');
                db.query("DELETE FROM tokens",function (err) {
                    if (err) cb(err);
                    db.query("DELETE FROM users WHERE NOT username=\'root\'",function (err) {
                        if (err) cb(err);
                        db.query("DELETE FROM eve_accounts",function (err) {
                            if (err) cb(err);
                            db.query("DELETE FROM privileges",function (err) {
                                if (err) cb(err);
                                db.end([],cb);
                            })
                        })
                    });
                })
            },
            function (cb) {
                debug('getting root token');
                request.post('/login').send({username:"root",password:"root"})
                    .expect(function (res) {
                        res=JSON.parse(res.text);
                        roottoken=res.token;
                    }).expect(200,cb);
            },
            function (cb) {
                debug('registering users');
                async.each(users,function (user,cb2) {
                    request.post('/register').send(Object.assign({token:roottoken},user))
                        .expect(200,cb2);
                },cb);
            },
            function (cb) {
                debug('getting new user token');
                async.each(users,function (user,cb2) {
                    request.post('/login').send(user)
                        .expect(function (res) {
                            res=JSON.parse(res.text);
                            tokens.push(res.token);
                            uids.push(res.userid);
                        }).expect(200,cb2);
                },cb);
            }
        ],function (err) {
            if (err) throw err;
            debug('cleared all accounts and ready for test');
            for (let i=0;i<tokens.length;++i){
                debug("uid:"+uids[i]+" username:"+users[i].username+" token:"+tokens[i]);
            }
            done();
        });
    });
    it('should add eve account',function (done) {
        request.post('/accounts/add').send({token:tokens[0],account:JSON.stringify({username:"test",password:"test"})})
            .expect(function (res) {
                res=JSON.parse(res.text);
                aid1=res.id;
                debug('new account id:'+aid1);
            })
            .expect(200,done);
    });
    let chklogin=function (token,aid,exp,cb) {
        request.post('/accounts/login').send({token:token,account_id:aid})
            .expect(200,exp,cb);
    };
    it('should access eve account (in debug mode)',function (done) {
        chklogin(tokens[0],aid1,{username:"test",password:"test"},done);
    });
    it('should edit account',function (done) {
        request.post('/accounts/edit')
            .send({token:tokens[0],account_id:aid1,account:JSON.stringify({username:"test",password:"test-2"})})
            .expect(200).then(()=>{chklogin(tokens[0],aid1,{username:"test",password:"test-2"},done)});
    });
    it('should prevent others from visiting accounts',function (done) {
        request.post('/accounts/login')
            .send({token:tokens[1],account_id:aid1})
            .expect(403,done);
    });
    it('should let root access accounts',function (done) {
        chklogin(roottoken,aid1,{username:"test",password:"test-2"},done);
    });
    let chkget=function (tokenfrom,tokento,aid,to,exp,cb) {
        request.post('/accounts/give')
            .send({token:tokenfrom,account_id:aid,give_to:to,priv:"getToken"})
            .expect(200).then(()=>{chklogin(tokento,aid,exp,cb)});
    };
    it('should give others read perm. to access accounts',function (done) {
        chkget(tokens[0],tokens[1],aid1,uids[1],{username:"test",password:"test-2"},done);
    });
    it('should give others give perm. to accounts',function (done) {
        request.post('/accounts/give')
            .send({token:tokens[0],account_id:aid1,give_to:uids[2],priv:"give"})
            .expect(200).then(()=>{chkget(tokens[2],tokens[4],aid1,uids[4],{username:"test",password:"test-2"},done)});
    });
});