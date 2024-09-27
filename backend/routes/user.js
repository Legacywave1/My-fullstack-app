const express = require('express');
const bycrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const router = express.Route()
const db = require('../server')

router.post('/signup', async (req,res) => {
    const {email, password} = req.body;
    const hashedPassword = await bycrypt.hash(password, 10);

    db.query('INSERT INTO userdata(UPN, pasword) VALUES (?,?)', [email, hashedPassword] , (err) => { if (err) return res.status(500).send(err);
        res.status(201).send('User Registered succcesfully')
    })


})

router.post('/login', async (req, res) => {
    const {email, pasword} = req.body;

    db.query('SELECT * FROM userdata WHERE email = ?', [email], async(err, results) => {
        if (err || results.length === 0) return res.status(401).send('Invalid credentials');

        const user = results[0];
        const isMatch = await
        bycrypt.compare(pasword, userdata.pasword);

        if (!isMatch) return res.status(401).send('Invalid Credentials');

        res.json({token});
    });
});

module.exports = router;

