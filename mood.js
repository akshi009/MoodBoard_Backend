import express from 'express'
import mongoose from 'mongoose'
import bycrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { OAuth2Client } from 'google-auth-library'

const app = express()
const PORT = 3000

app.use(express.json())

const absoluteExpiry = Date.now() + 7 * 24 * 60 * 60 * 1000;

mongoose.connect('mongodb+srv://akshi20jain03:Akshijain@learnings.baxbn3r.mongodb.net/Moodboard').then(() => console.log('mongodb connected!!')).catch((error) => console.log(error, "in connecting db"))

const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String
});

const Users = new mongoose.model('users', UserSchema)
const secretKey = 'abcd1234'
const refreshsecretKey = 'refresh5678'


app.get('/getuser', async (req, res) => {
    try {
        const user = await Users.find()
        res.json(user)

    } catch (error) {
        console.log(error, 'error in getting user');
        res.status(500).send('Error getting user');
    }
})

app.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body
        const existinguser = await Users.findOne({ email })
        if (existinguser) return res.status(400).json({ success: false, message: "Email already exists" });
        const hashedpassword = await bycrypt.hash(password, 10)
        const newuser = new Users({ name, email, password: hashedpassword })
        await newuser.save();
        res.status(200).json({ success: true, message: "created sucessfully", newuser })

    } catch (error) {
        console.log(error, 'error in creating user');
        res.status(500).send('Error creating user');
    }

})

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body
        const existinguser = await Users.findOne({ email })
        if (!existinguser) return res.status(400).json({ success: false, message: "User Not Found" });
        const isPassword = await bycrypt.compare(password, existinguser.password)
        if (!isPassword) return res.status(400).json({ success: false, message: "Password incorrect!!" });
        const token = jwt.sign({
            id: existinguser.id,
            email: existinguser.email
        }, secretKey, { expiresIn: '1h' })

        const refreshToken = jwt.sign({
            id: existinguser.id,
            email: existinguser.email
        }, secretKey, { expiresIn: '7d' })

        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
            maxAge: 60 * 60 * 1000
        })
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        })
        res.json({
            success: true,
            message: "Login successful",
            user: {
                id: existinguser._id,
                name: existinguser.name,
                email: existinguser.email
            }
        })


    } catch (error) {
        console.log(error, 'error in Login user');
        res.status(500).send('Error login user');
    }
})

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];

    if (!token) return res.status(401).json({ message: "No token provided" });

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid token" });

        req.user = user;
        next();
    });
};

app.get('/verify', verifyToken, (req, res) => {
    res.json({ message: `Welcome! ${req.user.email}`, user: req.user });
})

app.post('/refresh', (req, res) => {
    const token = req.cookies.refreshToken
    if (!token) return res.status(401).json({ message: 'No refresh token provided' });

    jwt.verify(token, REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid refresh token' });

        const newAccessToken = jwt.sign(
            { id: user.id, email: user.email },
            ACCESS_TOKEN_SECRET,
            { expiresIn: '15m' }
        );

        const newRefreshToken = jwt.sign(
            { id: user.id, email: user.email, absExp: absoluteExpiry },
            REFRESH_TOKEN_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('access_token', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 15 * 60 * 1000
        });

        res.cookie('refresh_token', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ message: 'Access and refresh tokens refreshed' });

    }
    )

})

app.post('/logout', (req, res) => {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.json({ message: 'Logged out' });
});

const client = new OAuth2Client('16471765044-3r3hsgbfispb81lubden1qtig1jefvs9.apps.googleusercontent.com')

app.post('/auth/google', async (req, res) => {
    try {
        const { token } = req.body
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: '16471765044-3r3hsgbfispb81lubden1qtig1jefvs9.apps.googleusercontent.com'
        })
        const payload = ticket.getPayload()
        const { email, name } = payload

        let user = UserSchema.findOne({ email })
        if (!user) {
            user = new Users({ name, email, password: null }); // No password for Google users
            await user.save();
        }

        const accessToken = jwt.sign({ id: user._id, email: user.email }, secretKey, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ id: user._id, email: user.email }, refreshsecretKey, { expiresIn: '7d' });

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 15 * 60 * 1000
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({
            success: true,
            message: "Google Login successful",
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {
        console.error("Google Auth Error:", error);
        res.status(401).json({ success: false, message: "Invalid Google token" });
    }
})

app.listen(PORT, () => { console.log(`Listening to PORT:${PORT}`) })