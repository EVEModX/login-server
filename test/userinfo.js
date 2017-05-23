"use strict";
let app = require('../app');
const request = require('supertest')('http://localhost:8080');
const should = require('should');
const debug = require('debug')('test');
const sqlite3 = require('sqlite3');
const async = require("async");
function login(user, pass) {
    return new Promise((resolve, reject) => {
        request.post("/login").send({username: user, password: pass})
            .expect(200)
            .expect((res) => {
                let result = {};
                try {
                    result = JSON.parse(res.text);
                } catch (e) {
                    if (e instanceof SyntaxError)
                        reject(res.text);
                }
                debug("login resolve " + result.token, result.userid);
                resolve({token:result.token, userid:result.userid});
            }).catch(err => {
            debug(err);
            reject(err);
        })
    });
}
describe('userinfo Module', function () {
    let token = "", userid = 0;
    before('init user', function (done) {
        login("root", "root").then(data => {
            let db = new sqlite3.Database(__dirname + "/../test.sqlite3");
            db.run("DELETE FROM users WHERE username=\'info-1\'", (err) => {
                if (err) throw err;
                request.post("/register").send({token: data.token, username: "info-1", password: "info-1"})
                    .expect(200).then(() => {
                    login("info-1", "info-1").then(data => {
                        token = data.token;
                        userid = data.userid;
                        done();
                    }).catch((err) => debug(err));
                }).catch((err) => debug(err));
            });
        }).catch((err) => debug(err));
    });
    it('should set user info', function (done) {
        let userinfo = JSON.stringify({email: "foo@bar.com", age: 20, birthday: "1970-1-1"});
        request.post("/user/setinfo").send({token: token, info_req: userinfo})
            .expect(200, done);
    });
    it('should get user info', function (done) {
        request.post("/user/getinfo").send({userid: userid, info_req: "{\"email\":\"\"}"})
            .expect(200)
            .expect({email: "foo@bar.com"}, done);
    });
    it('should process wrong requests',done => {
        request.post("/user/getinfo").send({userid:userid,info_req:"{"})
            .expect(400,done);
    });
    it('should return 404 if user don\'t exist',done=>{
        request.post("/user/getinfo").send({userid:-1,info_req:"{\"email\":\"\"}"})
            .expect(404,done);
    });
});