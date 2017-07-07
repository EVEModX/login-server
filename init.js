"use strict";
const mysql=require("mysql");
const config=require("./config");
const crypto=require("crypto");
let db=mysql.createConnection(config.mysql);

db.connect(err =>{
    if (!err) return;
    console.log("Error in connecting");
    console.log(err.code);
    if (err.fatal) process.exit();
});

let tables=[];
tables.push("DROP TABLE IF EXISTS users");
tables.push("CREATE TABLE users(" +
    "username VARCHAR(128) UNIQUE NOT NULL," +
    "userid INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT," +
    "password VARCHAR(32)," +
    "password_salt VARCHAR(32)" +
    ")");
tables.push("DROP TABLE IF EXISTS privileges");
tables.push("CREATE TABLE privileges(" +
    "role VARCHAR(32)," +
    "resource VARCHAR(32)," +
    "action VARCHAR(32)," +
    "perm BOOLEAN," +
    "CONSTRAINT pair UNIQUE(role,resource,action)" +
    ")");
tables.push("DROP TABLE IF EXISTS tokens");
tables.push("CREATE TABLE tokens(" +
    "token VARCHAR(32)," +
    "expiretime INTEGER," +
    "userid INTEGER" +
    ")");
tables.push("DROP TABLE IF EXISTS userinfo");
tables.push("CREATE TABLE userinfo(" +
    "id INTEGER NOT NULL PRIMARY KEY," +
    "data TEXT)");
tables.push("DROP TABLE IF EXISTS eve_accounts");
tables.push("CREATE TABLE eve_accounts ("+
    "id INTEGER PRIMARY KEY AUTO_INCREMENT NOT NULL,"+
    "owner INTEGER NOT NULL,"+
    "username VARCHAR(256),"+
    "password VARCHAR(256),"+
    "CONSTRAINT one_account UNIQUE(username,password,owner)"+
    ");");
for (let i=0;i<tables.length;i++){
    db.query(tables[i],[],(err)=>{
        if (err) {
            console.log("ERROR ON " + tables[i]);
            console.log(err);
        }
    });
}
console.log("table created");
let regroot=new Promise((resolve,reject)=>{
    crypto.randomBytes(16,(err,buf)=>{
        if (err) reject(err);
        crypto.pbkdf2("root",buf,config.security.pbkdf2_iter,16,'sha512',(err,key)=>{
            if (err) reject(err);
            db.query("INSERT INTO users(username,password,password_salt) VALUES('root',?,?)",
                [key.toString('hex'),buf.toString('hex')],(err)=>{
                if (err) reject(err);
                resolve();
                });
        })
    });
});
console.log("Initialing Database...");
regroot.then(()=>{
    console.log("root user created.\nDone.");
    process.exit();
});