//encoding:utf-8
/*
* account模块测试集
* */
var app=require('../app');
var request=require('supertest')('http://localhost:8080');
var should=require('should');
var debug=require('debug')('test');
var sqlite3=require('sqlite3');
var redis=require('redis'),
    rdsclient=redis.createClient();
var async = require("async");
describe('accounts module',function () {
    var tokens=[];
    var roottoken;
    var users=[{username:"pibc",password:"pibc"},{username:"tga",password:"tga"},{username:"fbp",password:"fbp"}];
    var db=new sqlite3.Database(__dirname+"/../test.sqlite3");
    before('clear all accounts and privileges',function (done) {
        this.timeout(5000);
        async.series([
            function (cb) {
                db.run("DELETE FROM tokens",function (err) {
                    if (err) cb(err);
                    db.run("DELETE FROM users WHERE NOT username=\'root\'",function (err) {
                        if (err) cb(err);
                        db.close(cb);
                    });
                })
            },
            function (cb) {
                rdsclient.flushall(cb);
            },
            function (cb) {
                request.post('/login').send({username:"root",password:"root"})
                    .expect(function (res) {
                        res=JSON.parse(res.text);
                        roottoken=res.token;
                    }).expect(200,cb);
            },
            function (cb) {
                async.each(users,function (user,cb2) {
                    request.post('/register').send(Object.assign({token:roottoken},user))
                        .expect(200,cb2);
                },cb);
            },
            function (cb) {
                async.each(users,function (user,cb2) {
                    request.post('/login').send(user)
                        .expect(function (res) {
                            res=JSON.parse(res.text);
                            tokens.push(res.token);
                        }).expect(200,cb2);
                },cb);
            }
        ],function (err) {
            if (err) throw err;
            debug('cleared all accounts and ready for test');
            done();
        });
    });
    it('should add eve account',function (done) {
        request.post('/accounts/add').send({token:tokens[0],account:JSON.stringify({username:"test",password:"test"})})
            .expect(200,done);
    });
    it('should get eve account');
});