import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import session from "express-session";
import bcrypt from "bcrypt";
import { error } from "node:console";

const app = express();
const port = 3000;
env.config();
const saltRounds = 10;

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use( session({
    secret: process.env.SESSION_SECRET || "supersecretkey", 
    resave: false,                                         
    saveUninitialized: false,                              
    cookie: { maxAge: 1000 * 60 * 60 * 24 }
  })
);

const db = new pg.Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect((err, client, release) => {
  if (err) {
    console.error("DB connection error:", err.stack);
  } else {
    console.log("Successfully connected to the PostgreSQL DB");
    release(); 
  }
});

//response to request for the home page
app.get("/", (req, res) =>{
    try {
        return res.status(200).render("index.ejs");
    } catch (error) {
        console.log("An error occured: ", error.stack);
        return res.status(500).render("index.ejs", {error: "Internal Server Error"})
    }
});

//to handle all verification when creating an account 
app.post("/createAccount", async (req,res) => {
  const fname = (req.body.FName || "").toLowerCase().trim();
  const lname = (req.body.LName || "").toLowerCase().trim();
  const email = (req.body.email || "").toLowerCase().trim();
  const password = (req.body.password || "").trim();
  const confirmPassword = (req.body.confirmPassword || "").trim();

  if (!fname || !lname || !email || !password || !confirmPassword) {  //my check against empty field
    return res.status(400).render("index.ejs", { error: "All fields are required" });
  }

  if (fname.length < 3 || lname.length < 3) { //my check against name length
    return res.status(400).render("index.ejs", { error: "First and last names must be 3 characters and above" });
  }

  if (!checkEmailStructureAndDomain(email)) { //my check against invalid domain and email structure
    return res.status(400).render("index.ejs", { error: "Invalid email domain. Please use a valid email address." });
  }

  if (!checkPassword(password)) { //my password check
    return res.status(400).render("index.ejs", { error: "minimum 8 characters and must include Capital letter, A Number and Special Character" });
  }

  if (!checkConfirmPassword(confirmPassword)) { //my confirm password check
    return res.status(400).render("index.ejs", { error: "confirmPassword must be same as password " });
  }

  try { // insert into DB if all checks are successful
    const checkEmailDuplicity = await db.query("SELECT email FROM userdb WHERE email = $1", [email]);

    if (checkEmailDuplicity.rows.length > 0) {
      console.log("Email already exists in the database:", email);
      return res.status(400).render("index.ejs", { error: "Email exists. Try Login" });
    }

    //next implementing password hashing for security
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    //if all verification successful inssert into DB and return RETURNING id for session handling
    const result = await db.query(
      "INSERT INTO userdb (fname, lname, email, password) VALUES ($1, $2, $3, $4) RETURNING id", 
      [fname, lname, email, hashedPassword]
    );
    
    //to store new created user id in a session
    req.session.currentUserId = result.rows[0].id;

    console.log("User registered and logged in with ID:", req.session.currentUserId);
    return res.redirect("/userDashboard"); 
  } catch (error) {
    console.error("An error occurred:", error.stack);
    return res.status(500).render("createAccount.ejs", { error: "Internal Server Error" });
  }
});



// to render the login page
app.get("/loginPageNav", (req, res) =>{
    try {
        return res.status(200).render("loginPage.ejs");
    } catch (error) {
        console.log("An error occured: ", error.stack);
        return res.status(500).render("loginPage.ejs", {error: "Internal Server Error"})
    }
});

//to handle all verification when trying to login a user
// app.post("/loginUser", async (req,res) => {
//   const email = (req.body.email || "").toLowerCase().trim();
//   const password = (req.body.password || "").trim();

//   if (!email || !password) {  //my check against empty field
//     return res.status(400).render("loginUser.ejs", { error: "All fields are required" });
//   }

//   if (hasInvalidEmailDomain(email)) { //my check against invalid domain
//     return res.status(400).render("loginUser.ejs", { error: "Invalid email domain. Please use a valid email address." });
//   }

//   try { // to check the DB if the accounts xist
//     const checkDetails = await db.query("SELECT id, email, password FROM user_reg_table WHERE email = $1", [email]);

//     if (checkDetails.rows.length === 0) {
//       return res.status(400).render("loginUser.ejs", { error: "Incorrect Details" });
//     }

//     const user = checkDetails.rows[0];
    
//     //now i want to Compare entered plain-text password with stored hashed password
//     const isPasswordMatch = await bcrypt.compare(password, user.password);

//     if (!isPasswordMatch) {
//       return res.status(400).render("loginUser.ejs", { error: "Incorrect Details" });
//     }

//     //to save user id in session on successful login
//     req.session.userId = user.id;

//     console.log("User logged in with ID:", req.session.userId);
//     return res.redirect("/userDashboard");

//   } catch (error) {
//     console.error("An error occurred:", error.stack);
//     return res.status(500).render("loginUser.ejs", { error: "Internal Server Error" });
//   }
// });

function checkEmailStructureAndDomain(email) {
  // Regex pattern
  
  const emailStructureRegex = /^[^\s@]+@[^\s@]+\.(com|net|org|edu|gov|io|co|ng)$/i;
  const typoPattern = /@(gmai|gmal|gmial|yaho|outloo|hotmai)\.(com|net|org)$/i;

  if (!emailStructureRegex.test(email) || typoPattern.test(email) ) {
    return false;
  }

  return true;
}

function checkPassword(password) {
  if (password.length < 8){
        return false;
    } else if(!/[A-Z]/.test(password)){
        return false;
    } else if(!/[0-9]/.test(password)){
        return false;
    } else if(!/[^A-Za-z0-9]/.test(password)){
        return false;
    }

  return true;
}

function checkConfirmPassword(confirmPassword) {
  if (confirmPassword !== password) {
        return false;
    } 

  return true;
}

app.listen(port, () => { 
  console.log(`Server running on port: ${port}`);
}); 