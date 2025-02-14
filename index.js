import dotenv from "dotenv";
import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const port = 3000;

app.use(express.static("public"));
app.use(express.json());

const pool = new pg.Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

const auth = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).json({
    msg: 'No token, authorization denied.'
  });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({
      msg: "Token is not valid"
    });
  }
};

app.post("/api/users/register", async (req, res) => {
  try {
    const {
      username, email, password, fullName, gender, dateOfBirth, country
    } = req.body;
    const userCheck = await pool.query("SELECT * FROM users WHERE username = $1 OR email = $2", [username, email]);

    if (userCheck.rows.length > 0) {
      return res.status(400).json({
        msg: "User already exists"
      });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await pool.query("INSERT INTO users (username, email, password, full_name, gender, date_of_birth, country) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id", [username, email, hashedPassword, fullName, gender, dateOfBirth, country]);

    const userId = newUser.rows[0].id;

    const payload = {
      user: {
        id: userId
      }
    };
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

app.post("/api/users/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const userResult = await pool.query("SELECT * FROM users WHERE username = $1", [username]);

    if (userResult.rows.length === 0) {
      return res.status(400).json({
        msg: "Invalid user credentials"
      });
    }
    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        msg: "Invalid user credentials"
      });
    }
    const payload = {
      user: {
        id: user.id,
      },
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '1h' },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.get('/api/users/search/:query', auth, async (req, res) => {
  try {
    const { query } = req.params;
    const userResult = await pool.query("SELECT id, username, email, full_name, gender, date_of_birth, country FROM users WHERE username = $1 OR email = $1", [query]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        msg: "User not found"
      });
    }
    res.json(userResult.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
