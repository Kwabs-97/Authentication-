import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "kwabs",
  port: 5432,
});
db.connect();

const saltRounds = 10;


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));


//session middleware configuration
app.use(session({
  secret:"TOPSECRET",
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 6000 * 60 * 60 * 24 
  }
}))


//passport configuration.. Should always come after session middleware configuration
app.use(passport.initialize());
app.use(passport.session());


app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req,res) => {
req.isAuthenticated() ? res.render("secrets.ejs") : res.redirect("/login");
})

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //password hashing
      bcrypt.hash(password, saltRounds, async (err,hash) => {
        console.log(hash);
        const result = await db.query(
          "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING * ",
          [email, hash]
        );
       const user = result.rows[0];
       req.login(user, (err) => {
        res.redirect("/secrets");
       })
      })
    
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
}));

passport.use(new Strategy( async function verify(username,password, callback){
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;

      //compare the storedHashedPassword with the login Password
      bcrypt.compare(password, storedHashedPassword, (err, result)=>{
if(err){
 return callback(err);
}else{
  if(result){
    return callback(null, user);
  } else {
    return callback(err, false);
  }
}
      });
     
    } else {
      return callback("User not found");
    }
  } catch (err) {
    return callback(err);
  }
}));

passport.serializeUser((user, cb) => {
cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
