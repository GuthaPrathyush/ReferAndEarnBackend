const express = require('express');
const app = express();
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { resolve } = require('path');
const cryptoLength = 16;

function generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex').slice(0, length); 
}

async function isUniqueCode(refferalCode) {
    const query2 = `SELECT Reference_Code FROM users where Reference_Code = '${refferalCode}'`;
    return new Promise((resolve, reject) => {
        db.query(query2, (err2, result2) => {
            if(err2) {
                reject(false);
            }   
            if(result2.length > 0) {
                reject(false);
            }
            else {
                resolve(true);
            }
        });
    });
}

async function generateUniqueRandomString(length) {
    let code;
    let unique = false;

    while (!unique) {
        code = generateRandomString(length);
        await isUniqueCode(code).then(uCode => unique = uCode).catch(err => unique = false);
    }
    return code;
}

const saltRounds = 13;
const port = 3000;
const jwtString = "asdlfjEHuadhUsdHSdjeq";

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "referandearn"
});

const corsOptions = {
    origin: 'https://refer-and-earn-virid.vercel.app', // replace with frontend code;
    methods: ['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'auth-token']
}

app.use(express.json());
app.use(cors(corsOptions));

app.options('*', cors(corsOptions));

app.get('/', (req, res) => {
    res.send('API is running');
})

app.post('/login', async (req, res) => {
    const query = `SELECT Password, ID FROM users WHERE Email = '${req.body.Email}'`;
    let password = null;
    let id = null
    db.query(query, async(err, result) => {
        if(err) {
            return res.status(500).json({success: false, errors: "Unable to Login"});
        }
        if(result.length > 0) { 
            password = result[0].Password;
            id = result[0].ID;
        }
        else {
            return res.status(400).json({success: false, errors: "User not found"});
        }
        const isPasswordValid = await bcrypt.compare(req.body.Password, password);
        if (!isPasswordValid) {
            return res.status(400).json({ success: false, errors: "Wrong Password" });
        }
        const data = {
            user: {
                id: id
            }
        }
        const token = jwt.sign(data, jwtString);
        res.json({success: true, message: "Login Successful!", token});
    });
});

app.post('/register', async(req, res) => {
    const query = `SELECT Name FROM users WHERE Email = '${req.body.Email}'`;
    const hashedPassword = await bcrypt.hash(req.body.Password, saltRounds).catch((error) => {
        return res.status(500).json({success: false, errors: "Internal Server error"});
    });
    db.query(query, (err, result) => {
        if(err) {
            return res.status(500).json({success: false, errors: "Internal Server Error"});
        }
        if(result.length > 0) {
            return res.status(400).json({success: false, errors: "User Already Exists"});
        }
        else {
            const query2 = `INSERT INTO users(Name, Email, Password) VALUE('${req.body.Name}', '${req.body.Email}', '${hashedPassword}')`;
            db.query(query2, (err2, result2) => {
                if(err2) {
                    return res.status(500).json({success: false, errors: "Internal Server Error"});
                }
                else {
                    res.json({success: true, message: "User Successfully Registered"});
                }
            });
        }
    });
});

app.post('/getUserData', async(req, res) => {
    const token = req.header('auth-token');
    if(!token) {
        return res.status(400).json({success: false, errors: "Please pass an auth-token"});
    }
    let id;
    try {
        const userData = jwt.verify(token, jwtString);
        id = userData.user.id;
    }
    catch(err) {
        return res.status(401).json({success: false, errors: "Invalid auth-token"});
    }
    const query = `SELECT Reference_Code, Wallet_Balance FROM users where ID = '${id}'`;
    db.query(query, async (err, result) => {
        if(err) {
            return res.status(500).json({success: false, errors: "Internal Server Error1"});
        }
        if(result.length > 0) {
            const userData = result[0].Reference_Code;
            const wallet = result[0].Wallet_Balance;
            res.json({success: true, userData: {Reference_Code: userData, Wallet_Balance: wallet}, message: "Success!"});
        }
        else {
            return res.status(400).json({success: false, errors: "No user details found"});
        }
    });
});

app.post('/getNewReferralCode', async(req, res) => {
    const token = req.header('auth-token');
    if(!token) {
        return res.status(400).json({success: false, errors: "Please pass an auth-token"});
    }
    let id;
    try {
        const userData = jwt.verify(token, jwtString);
        id = userData.user.id;
    }
    catch(err) {
        return res.status(401).json({success: false, errors: "Invalid auth-token"});
    }
    const query = `SELECT Wallet_Balance FROM users where ID = '${id}'`;
    db.query(query, async (err, result) => {
        if(err) {
            return res.status(500).json({success: false, errors: "Internal Server Error1"});
        }
        if(result.length > 0) {
            const wallet = result[0].Wallet_Balance;
            let Reference_Code_New;
            try {
                Reference_Code_New = await generateUniqueRandomString(cryptoLength)
            }
            catch(err) {
                return res.status(500).json({success: false, errors: "Internal Server Error"});
            }
            const query2 = `UPDATE users SET Reference_Code = '${Reference_Code_New}' WHERE ID = '${id}'`;
            db.query(query2, (err, result) => {
                if(err) {
                    return res.status(500).json({success: false, errors: "Internal Server Error3"});
                }
                else {
                    return res.json({success: true, userData: {Reference_Code: Reference_Code_New, Wallet_Balance: wallet}, message: "New Reference code created!"});
                }
            });
        }
        else {
            return res.status(400).json({success: false, errors: "No user details found"});
        }
    });
});

function queryDatabase(query, params) {
    return new Promise((resolve, reject) => {
        db.query(query, params, (error, results) => {
            if (error) return reject(error);
            resolve(results);
        });
    });
}

app.post('/verifyReferralCode', async (req, res) => {
    const token = req.header('auth-token');
    if (!token) {
        return res.status(400).json({ success: false, errors: "Please pass an auth-token" });
    }

    let id;
    try {
        const userData = jwt.verify(token, jwtString);
        id = userData.user.id;
    } catch (err) {
        return res.status(401).json({ success: false, errors: "Invalid auth-token" });
    }

    try {
        const result = await queryDatabase(`SELECT Reference_Code FROM users WHERE ID = ?`, [id]);

        if (result.length > 0 && result[0].Reference_Code !== "") {
            return res.status(401).json({ success: false, errors: "Referral Code already found! Unfortunately You cannot Claim..." });
        }

        if(result.length > 0) {

            const result2 = await queryDatabase(`SELECT Name FROM users WHERE Reference_Code = ?`, [req.body.Referral_Code]);

            if (result2.length > 0) {
                const referral_code = req.body.Referral_Code;
                const Reference_Code_New = await generateUniqueRandomString(cryptoLength);

                await queryDatabase('START TRANSACTION');

                try {
                    await queryDatabase(`UPDATE users SET Wallet_Balance = Wallet_Balance + 7000 WHERE Reference_Code = ?`, [referral_code]);
                    await queryDatabase(`UPDATE users SET Wallet_Balance = Wallet_Balance + 9000, Reference_Code = ? WHERE ID = ?`, [Reference_Code_New, id]);
                    await queryDatabase('COMMIT');
                    return res.json({ success: true, message: "Referral Code Accepted!" });
                } catch (err) {
                    await queryDatabase('ROLLBACK');
                    return res.status(500).json({ success: false, errors: "Internal Server Error" });
                }
            } else {
                return res.status(400).json({ success: false, errors: "User not found" });
            }
        }
        else {
            return res.status(400).send({success: false, errors: "User not found"});
        }
    } catch (err) {
        return res.status(500).json({ success: false, errors: "Internal Server Error" });
    }
});


app.post('/tokenify', async(req, res) => {
    let data;
    let id;
    try {
        data = jwt.verify(req.body.token, jwtString);
        id = data.user.id;
    }
    catch(err) {
        return res.status(500).json({success: false, errors: err});
    }
    res.json({id: id});
})

app.listen(port, (err) => {
    if(!err) {
        console.log("app is listening at port " + port);
    }
    else {
        console.log(err);
    }
})

