require('dotenv').config();

const express = require('express');

const session = require('express-session');



require("./absoluteFile.js");

const Joi = require("joi");

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
app.get('/', (req,res) => {
    
    var name = req.session.username;
    if (!req.session.authenticated) {
        var html = `
        <form action = '/signup' method ='get'>
        <button>Sign Up</button> 
        </form>
    
        <form action = '/login' method ='get'>
            <button>Log In</button>
        </form>` 
    }else{
        var html = `Hello, ` + name +
        `<form action = '/members' method ='get'>
        <button>Member's Area</button> 
        </form>
    
        <form action = '/logout' method ='get'>
            <button>Log Out</button>
        </form>`
    }
   
    res.send(html);
});


app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    var html = `<h1>Hello ${username}</h1> 
    <br></br> 
    <button>Go to member's Area</button>
    <br></br> 
    <button>Log Out</button>`
    res.send(html);
});

app.get('/signup',(req,res) => {
    var form = `
    Create User:
    <form action='/submitUserSignup' method='post'>
        <input name='username' type='text' placeholder='name'>
        <p>\n</p>
        <input name='email' type='text' placeholder='email'>
        <p>\n</p>
        <input name='pwd' type='password' placeholder='password'>
        <p>\n</p>
        <button>Submit</button>
    </form>`
    res.send(form);
    
})


app.get('/userInfo', (req,res) => {
    var missingInfo = req.query.missing;
    var userStatus = req.query.user;
    var html ='';
    if (missingInfo == 'name') {
         html += "<b>name is required</b>";
    } else if(missingInfo == 'email'){
        html += " <b>email is required</b>";
    }else if(missingInfo == 'password'){
        html += "<b>password is required</b>";
    } else if(userStatus == "duplicate"){
        html += "The <b>username already exists, please try a different username!</b>";
    }
    html += `<br> <a style='color:blue;' href='/signup'>Try again</a>`;
    res.send(html);
});

app.post('/submitUserSignup', async (req,res) => {
    var name = req.body.username;
   
    var email = req.body.email;
    var password = req.body.pwd;
    const result = await userCollection.find({username: name}).project({username: 1, password: 1, _id: 1}).toArray();
    if (!name) {
        res.redirect('/userInfo?missing=name');
    } else if(!email){
        res.redirect('/userInfo?missing=email');
    } else if(!password){
        res.redirect('/userInfo?missing=password');
    } else if(result.length == 1) {
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
                console.log("trying to insert");
                var hashedPassword = await bcrypt.hash(password, rounding);
                await userCollection.insertOne({username: name, email: email, password: hashedPassword});
                console.log("Inserted user");
                req.session.username = name;
                console.log(timeUntilExpires);
                req.session.cookie.maxAge = timeUntilExpires;
                console.log(req.session.cookie.maxAge);
                req.session.authenticated = true;
                console.log("Added session");
                res.redirect(`/members`);
                console.log("redirecting ...");
                console.log("Eror: " + validationResult);
               }
    }
    
});

app.get('/login',(req,res) => {
    var form = `
    Log In
    <form action='/loggingIn' method='post'>
        <input name='email' type='text' placeholder='email'>
        <p>\n</p>
        <input name='pwd' type='password' placeholder='password'>
        <p>\n</p>
        <button>Submit</button>
    </form>`
    res.send(form);
    
})

app.get('/submitLogin', (req,res) => {
    var athenticationState = req.query.authentication;
    var html=''
    if (athenticationState == 'failed') {
        html += "<br> Email or Password not found!";
        html += `<br> <a style='color:blue;' href= '/login'>Try again</a>`;
    } 
    else{
        return;
    }
    res.send(html);
});

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

    const result = await userCollection.find({email: email}).project({username: 1, password: 1}).toArray();

    if (result.length != 1) {
		console.log("email not found");
		res.redirect("/submitLogin?authentication=failed");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = result[0].username;
		req.session.cookie.maxAge = timeUntilExpires;
		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/submitLogin?authentication=failed");
		return;
	}
})

app.get('/members',(req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }else{
        const min = 1;
        const max = 3;
        const randomNum = Math.floor(Math.random() * (max - min + 1) + min);
        //get username from db
        var name = req.session.username;
        var text = `Hello, ` + name + '<br></br>';
        if(randomNum == 1){
            text+= `<img src='/bulbasaur.jpg'>`
        } else if(randomNum == 2){
            text+= `<img src='/charmander.jpg'>`
        }else if(randomNum == 3){
            text+= `<img src='/squirtle.png'>`
        } else {
            text+= `invalid number'>`
        }
        text+= `<br></br><a href='/logout'>Log Out</a>`
        res.send(text);
    }
    
})

app.get('/logout',(req,res) => {
    req.session.authenticated = false;
    req.session.destroy();
    res.redirect('/');
    
})

app.use(express.static(__dirname + "/public"));

app.get('/*',(req,res) => {
    res.status(404);
   res.send(`Page not found - 404`)
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
});