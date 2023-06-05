const express = require("express");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const app = express();
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");
const { Client, Environment } = require("square");
require("dotenv").config();

const querystring = require("querystring");
const axios = require("axios");
const session = require("express-session");
const crypto = require("crypto");
const client = new Client({
  environment: Environment.Production,
  accessToken:
    "EAAAFGvYieKTwthuCnhaqXF1Yr-gjvwQa1WDZX9KRWPPAJcsMfWdr4g6wsi1xkCy",
  clientId: "sq0idp-Krs43HDBnz1TcueZBIXjPw",
});

const SQUARE_APP_SECRET = "sq0csp-ZpJ2m2k8POn3Vs2gQMccC7Cc4Gxc2Vvq9br6Z7KiVhs";
const SQUARE_APP_REDIRECT_URL =
  "https://curious-cashflow-api.onrender.com/api/square/oauth/callback";

BigInt.prototype.toJSON = function () {
  return this.toString();
};

app.use(cookieParser());
app.use(
  cors({
    credentials: true,
    origin: ["http://localhost:3000", "https://curious-cashflow.onrender.com"],
  })
); // restrict CORS to only your React app:

app.use(express.json()); // for parsing application/json
app.use(
  session({
    secret: "FOODFOR002", // you should choose your own secret value here
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // 'auto' means use secure cookies over HTTPS, non-secure over HTTP
  })
);
// app.get("/set-cookie", (req, res) => {
//   res.cookie("test", "value");
//   res.send("Cookie set");
// });

// app.get("/check-cookie", (req, res) => {
//   console.log(req.cookies.test); // This should log 'value' if the cookie was correctly set and parsed
//   res.send("Check console");
// });
mongoose.connect(
  `mongodb+srv://luisdmoralesh:${process.env.MONGODB_PASSWORD}.@businesstracker.bqwgtlj.mongodb.net/`,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
);

const User = mongoose.model(
  "User",
  new mongoose.Schema({
    businessName: String,
    email: { type: String, unique: true },
    password: String,
    squareAccessToken: { type: String, default: "" },
  })
);

const Job = mongoose.model(
  "Job",
  new mongoose.Schema({
    businessOwnerId: String,
    title: String,
    description: String,
    clientName: String,
    clientEmail: String,
    clientPhone: String,
    totalCost: String,
    createdAt: Date,
    status: String,
    sourceType: String,
    orderID: String,
    receiptUrl: String,
  })
);

app.post("/user", authenticateToken, async (req, res) => {
  const { businessOwnerId } = req.body;

  try {
    const user = await User.findById(businessOwnerId);
    console.log(user);
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

app.put("/user", authenticateToken, async (req, res) => {
  const { businessOwnerId, newBusinessName } = req.body;

  try {
    // Find the user by businessOwnerId and update the businessName field
    const updatedUser = await User.findById(businessOwnerId);
    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }
    updatedUser.businessName = newBusinessName;
    await updatedUser.save();
    res.status(200).json({ message: "Business Name Updated" });
  } catch (error) {
    res.status(500).json({ error: "Failed to update user" });
  }
});

app.post("/job", authenticateToken, async (req, res) => {
  try {
    const job = new Job(req.body);
    await job.save();
    res.json(job);
  } catch (error) {
    res.status(500).json({ error: "Error saving Job into Database" });
  }
});

app.delete("/job/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const job = await Job.findByIdAndDelete(id);

    if (!job) {
      return res.status(404).json({ message: "Job not found" });
    }

    res.json({ message: "Job deleted" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});
app.post("/api/register", async (req, res) => {
  const { businessName, email, password } = req.body;
  // TODO: Add input validation here
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ businessName, email, password: hashedPassword });
  try {
    await user.save();
    res.status(201).send({ message: "User created successfully" });
  } catch (error) {
    if (error.code === 11000) {
      // This error occurs if the email is already in use
      res.status(400).send({ message: "Email is already in use" });
    } else {
      res.status(500).send({ message: "Internal server error" });
    }
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await getUserByEmail(email); // Replace with your own function to get a user from your database
    if (!user) {
      res.status(400).send({ message: "Invalid email or password" });
      return;
    }
    bcrypt.compare(password, user.password, (error, result) => {
      if (error) {
        res.status(500).send({ message: "Internal server error" });
      } else if (result) {
        // Here, you might want to create a session or generate a token for the user
        const token = jwt.sign(
          {
            email: user.email,
            businessName: user.businessName,
          },
          "FOODFOR002",
          { expiresIn: "1h" }
        );
        // Store OwnerID for later use during Job Creation
        // OwnerID is disposed after LogOut
        const id = user._id.toString();
        res.send({
          message: "Successfully logged in",
          user: {
            businessName: user.businessName,
            email: user.email,
            id,
            squareAccessToken: !!user.squareAccessToken,
          },
          token: token,
        });
      } else {
        res.status(400).send({ message: "Invalid email or password" });
      }
    });
  } catch (error) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/api/jobs", authenticateToken, async (req, res) => {
  const { businessOwnerId } = req.body;

  try {
    const jobs = await Job.find({ businessOwnerId });
    res.json(jobs);
  } catch (error) {
    res.status(500).json({ error: `error fetching jobs: ${error.toString()}` });
  }
});

app.listen(3001, () => {
  console.log("Server is running on port 3001");
});

app.post("/api/payments", authenticateToken, async (req, res) => {
  const { businessOwnerId, clientEmail, totalCost } = req.body;
  const clientToEnter = clientEmail == "" ? "bot@gmail.com" : clientEmail;
  const idempotencyKey = uuidv4();
  const amountToEnter = Number(totalCost);

  // Retrieve the Square access token for the business owner
  const businessOwner = await User.findById(businessOwnerId);
  const squareAccessToken = decrypt(businessOwner.squareAccessToken);

  // Set the Square client to use this access token
  const squareClient = new Client({
    environment: Environment.Production,
    accessToken: squareAccessToken,
  });

  try {
    const response = await squareClient.paymentsApi.createPayment({
      sourceId: "CASH",
      idempotencyKey: idempotencyKey,
      amountMoney: {
        amount: amountToEnter * 100,
        currency: "GBP",
      },
      autocomplete: true,
      acceptPartialAuthorization: false,
      buyerEmailAddress: clientToEnter,
      cashDetails: {
        buyerSuppliedMoney: {
          amount: amountToEnter * 100,
          currency: "GBP",
        },
      },
    });
    console.log("------------------");
    console.log(response.result);
    res.json(response.result);
  } catch (error) {
    console.log(`Error occurred while creating payment: `, error);
    res
      .status(500)
      .send({ error: "An error occurred while creating the payment" });
  }
});

// AUTHENTICATE TOKEN NEEDS TO WORK HERE
// BUT WE NEED TO USE COOKIES FOR THAT.
// MAYBE LATER
app.post("/api/square/oauth", authenticateToken, (req, res) => {
  const state = uuidv4();
  req.session.oauthState = state;
  req.session.userId = req.user.id;
  req.session.save((err) => {
    // handle error
  });

  const authorizeUrl = `https://connect.squareup.com/oauth2/authorize?${querystring.stringify(
    {
      client_id: client._config.clientId,
      response_type: "code",
      state: state,
      scope: "PAYMENTS_READ PAYMENTS_WRITE",
    }
  )}`;
  res.json({ authorizeUrl });
});

app.get("/api/square/oauth/callback", async (req, res) => {
  try {
    const { state, code } = req.query;

    if (state !== req.session.oauthState) {
      console.log(state);
      console.log(req.session.oauthState);
      // the state does  not match, so abort the process
      return res
        .status(400)
        .send(
          `Invalid state parameter state: ${state} oauthState: ${req.session.oauthState}`
        );
    }

    const response = await axios.post(
      "https://connect.squareup.com/oauth2/token",
      {
        client_id: client._config.clientId,
        client_secret: SQUARE_APP_SECRET,
        code,
        grant_type: "authorization_code",
      },
      {
        headers: {
          "Square-Version": "2021-05-13",
          "Content-Type": "application/json",
        },
      }
    );
    const { access_token } = response.data;

    // Save the access token for the user here
    // Use the userId from the session to fetch the user from the database
    const user = await User.findById(req.session.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const encryptedAccessToken = encrypt(access_token);
    user.squareAccessToken = encryptedAccessToken;
    await user.save();
    res.redirect("https://curious-cashflow.onrender.com/UserHome");
  } catch (error) {
    res.status(500).send({ message: "Internal server error" });
  }
});

async function getUserByEmail(email) {
  try {
    const user = await User.findOne({ email });
    return user;
  } catch (error) {
    return null;
  }
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (token) {
    jwt.verify(token, "FOODFOR002", (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      // If the token is verified, set req.user and call next()
      user.id = req.body.businessOwnerId;
      req.user = user;
      next();
    });
  } else {
    // Forbidden
    res.sendStatus(401);
  }
}

function encrypt(text) {
  var cipher = crypto.createCipher("aes-256-cbc", "d6F3Efeq");
  var crypted = cipher.update(text, "utf8", "hex");
  crypted += cipher.final("hex");
  return crypted;
}

function decrypt(text) {
  var decipher = crypto.createDecipher("aes-256-cbc", "d6F3Efeq");
  var dec = decipher.update(text, "hex", "utf8");
  dec += decipher.final("utf8");
  return dec;
}
