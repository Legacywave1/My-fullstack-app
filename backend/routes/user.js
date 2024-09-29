const express = require('express');
const bycrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const router = express.Router()
const cors = require('cors');
const mysql = require('mysql');
require('dotenv').config();

const app = express()
app.use(cors());
app.use(express.json());
app.use('/', router);

const PORT = process.env.PORT || 5000;


const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'mydatabase'
});

db.connect(err => {
    if (err) {
      console.error('Error connecting to database:', err);
      process.exit(1);
    }
    console.log('Connection successful');
  });

app.listen(PORT, () => {
    
    console.log(`Server is currently running on port ${PORT}`);
});

router.post('/signup', async (req, res) => {
    try {
        const { FirstName, LastName, UPN, DOB, UserID, password } = req.body;
        const hashedPassword = await bycrypt.hash(password, 10);

        db.query('INSERT INTO users (FirstName, LastName, UPN, DOB, UserID, password) VALUES (?, ?, ?, ?, ?, ?)', 
            [FirstName, LastName, UPN, DOB, UserID, hashedPassword], 
            (err, results) => {
                if (err) {
                    console.error('Error inserting user:', err);
                    return res.status(500).send({ error: 'Failed to register user', details: err });
                }
                console.log('User inserted successfully', results);
                res.status(201).send('User Registered successfully');
            }
        );
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body; 

    try {
        const [results] = await db.query('SELECT * FROM user WHERE email = ?', [email]);

        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = results[0]; 

        const isMatch = await bycrypt.compare(password, user.password); 

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        
        const token = jwt.sign({ userID: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' }); 

        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

router.post('/reset-password', async (req, res) => {
    const { email} = req.body;

    try {
        const [user] = await db.query('SELECT * FROM userdata WHERE email = ?', [email]);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const token = jwt.sign({ userID: user.id }. process.env.SECRET.KEY, { expiresIn: '1h' });

        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD
            }
        });

        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Reset Password',
            text: `Click here to reset your password: http://localhost:3000/reset-password/${token}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                res.status(500).json({ error: 'Failed to send email' });
            } else {
                res.json({message: 'Email sent successfully'});
    }

});
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

router.post('/reset-password/:token', async(req,res) =>{
    const { token } = req.params;
    const { password } = req.body;

    try {
        const decoded = jwt.verify(token, process.env.SECRET.KEY);

        const [user] = await db.query('SELECT * FROM userdata WHERE id = ?', [decoded.userID]);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const hashedPassword = await bycrypt.hash(password, 10);

        db.query('UPDATE userdata SET pasword = ? WHERE id = ?', [hashedPassword, decoded.userID], (err) => { if (err) return res.status(500).send(err);
            res.status(200).send('Password reset successfully')
    })
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

module.exports = router;

