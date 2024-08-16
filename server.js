const express = require('express');
const app =express() 
const cors=require("cors")

const {open} = require('sqlite');
const sqlite3 = require("sqlite3")
const path = require("path");

const bcrypt = require('bcrypt')
const dbpath = path.join(__dirname,"userauthentication.db")
const jwt = require("jsonwebtoken")
app.use(cors())
app.use(express.json())

let db=null

const intializeServerAndDB =async () => {
     try {db = await open ({
        filename:dbpath,
        driver:sqlite3.Database,
    })
    app.listen(3003,()=>{
        console.log("app running on server port no 3003")
    })
}
catch(e){
    console.log(`Db error ${e.message}`)
    process.exit(1)
}
}
intializeServerAndDB()

//signup  

app.post('/signup',async(request,response)=>{
    const {username,emailid,password} = request.body
    const hashedPassword = await bcrypt.hash(request.body.password,10)
    const getUser =`SELECT * FROM usercredentials WHERE username=?`
    const dbuser = await db.get(getUser,[username])
    if (dbuser===undefined){
        const newUserCreateQuery = `INSERT INTO usercredentials (username,emailid,password) VALUES (?,?,?)`
        const createUser = await db.run(newUserCreateQuery,[username,emailid,hashedPassword])
        response.send("user created successfully")
    }
    else {
        response.send("user already created")
    }

})

//login

app.post('/login',async(request,response)=>{
    const {username,password} = request.body 
    const loginDetails = `SELECT * FROM usercredentials WHERE username=?`
    const userlogin =await db.get(loginDetails,[username])
    if (userlogin==undefined){
            response.status=400 
            response.send('invalid user')
    }
    else{
        const isPasswordMatched = await bcrypt.compare(password,userlogin.password)
        if(isPasswordMatched){
            
            const payload = {username:username}
            const jwtToken = jwt.sign(payload,"mysecreattoken")
            response.send({jwtToken})

        }else{
            response.send("invalid password")
        }
    }
})







