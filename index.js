require('dotenv').config();

const express = require('express');

const session = require('express-session');



require("./absoluteFile.js");

const Joi = require("joi");

var url = require('url');

const app = express();

const MongoStore = require('connect-mongo');

const mongodb_host = process.env.MONGODB_HOST;

const mongodb_user = process.env.MONGODB_USER;

const mongodb_password = process.env.MONGODB_PASSWORD;

const mongodb_database = process.env.MONGODB_DATABASE;

const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

const rounding = 12;

const bcrypt = require('bcrypt');
const { name } = require('ejs');

const port = process.env.PORT || 3000;

const timeUntilExpires =  60 * 60 * 1000;

var {database} = include('dbConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
    
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/Assignment1-2537`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false,
    resave: true
}

));

function validSession(req){
    return req.session.authenticated;
}

function sessionValidation(req,res,next){
    console.log("vs: " + validSession(req));
    if(validSession(req)){
        next();
    }else{
        res.redirect('/');
    }
    
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("admin", {error: "Not Authorized - 403"});
        return;
    }
    else {
        next();
    }
}

app.set('view engine', 'ejs');

const navLinks = [
    {name: "Home", page: "/"},
    {name: "Log In", page: "/login"},
    {name: "Members", page: "/members"},
    {name: "Admin", page: "/admin"},
    {name: "404", page: "/dne"}
    
]

app.use("/",(req,res,next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
}) 
    


app.get('/', (req,res) => {
    var name = req.session.username;
    if(validSession(req)){
        res.render("index", {session: "valid",username: name });
    } else{
        res.render("index", {session: "invalid"});
    }  
});



app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	const schema = Joi.string().max(20).required();

	const validationResult = schema.validate(username);

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.render("noSql_attacks", {username: username, validation: validationResult.error })

});

app.get('/signup',(req,res) => {
    res.render("signup");
    
})


app.get('/userInfo', (req,res) => {
    var missingInfo = req.query.missing;
    var userStatus = req.query.user;
    res.render("userInfo",{missingInfo : missingInfo, userStatus: userStatus})
});

app.post('/submitUserSignup', async (req,res) => {
    var name = req.body.username;
   
    var email = req.body.email;
    var password = req.body.pwd;
    const existingResults = await userCollection.find({username: name}).project({username: 1, password: 1, _id: 1}).toArray();
    if (!name) {
        res.redirect('/userInfo?missing=name');
    } else if(!email){
        res.redirect('/userInfo?missing=email');
    } else if(!password){
        res.redirect('/userInfo?missing=password');
    } else if(existingResults.length == 1) {
        res.redirect('/userInfo?user=duplicate');
    } else {
        const schema = Joi.object(
                    {
                        username: Joi.string().allow('').alphanum().max(20),
                        password: Joi.string().allow('').max(20),
                        email: Joi.string().allow('').email().max(20)
                    });
                console.log("Name: " + name);
                const validationResult = schema.validate({username: name, password,email});
                console.log(validationResult);
                if (validationResult.error != null) {
                   //console.log(validationResult.error);
                   res.redirect("/signup");
                   return;
               } else{
           
                var hashedPassword = await bcrypt.hash(password, rounding);
                await userCollection.insertOne({username: name, email: email, password: hashedPassword, user_type: "user"});
                const newResult = await userCollection.find({email: email}).project({username: 1, password: 1,user_type: 1}).toArray();
                req.session.username = name;
                req.session.cookie.maxAge = timeUntilExpires;
                req.session.authenticated = true;
               req.session.user_type = newResult[0].user_type;
                res.redirect(`/members`);
               }
    }
    
});

app.get('/login',(req,res) => {
    res.render("login");
    
})

app.post('/loggingIn', async (req,res) => {
    var email = req.body.email;
    
    var password = req.body.pwd;

    const schema = Joi.object(
        {
            password: Joi.string().max(20).required(),
            email: Joi.string().email().max(20).required()
        });

    const validationResult = schema.validate({ password,email});

	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

    const result = await userCollection.find({email: email}).project({username: 1, password: 1,user_type: 1}).toArray();
    
    console.log("L: " + result.length);
    if (result.length != 1) {
		console.log("email not found");
		res.render("submitLogin");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
        console.log(result[0].user_type);
		req.session.authenticated = true;
		req.session.username = result[0].username;
		req.session.cookie.maxAge = timeUntilExpires;
        req.session.user_type = result[0].user_type;
		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		res.render("submitLogin");
		return;
	}
});

app.use("/members",sessionValidation)
app.get('/members',(req,res) => {
        var name = req.session.username;
        res.render("members",{username : name});
});

app.get('/logout',(req,res) => {
    req.session.authenticated = false;
    req.session.destroy();
    res.redirect('/');
    
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    console.log("on admin");
    const result = await userCollection.find().project({username: 1, user_type: 1}).toArray();
    console.log("r: " + result);
    res.render("admin",{error: "None", usersList: result});
});

app.post("/adminStatus", async (req, res) =>{
    console.log("changing status");
    var status = req.query.status;
    var user = req.query.user;
    if (status == "premote"){
        await userCollection.updateOne({username: user}, {$set: {user_type: 'admin'}});
    } else if(status == "demote"){
        await userCollection.updateOne({username: user}, {$set: {user_type: 'user'}});
    }
    res.redirect("/admin")
});

app.use(express.static(__dirname + "/public"));

app.get('/*',(req,res) => {
    res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
});