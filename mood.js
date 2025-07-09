import express from 'express'
import mongoose from 'mongoose'
import bycrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
const app = express()
const PORT = 3000

app.use(express.json())



mongoose.connect('mongodb+srv://akshi20jain03:Akshijain@learnings.baxbn3r.mongodb.net/Moodboard').then(() => console.log('mongodb connected!!')).catch((error) => console.log(error, "in connecting db"))

const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String
});

const Users = new mongoose.model('users', UserSchema)
const secretKey = 'abcd1234'


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
        res.json({
            success: true,
            message: "Login successful",
            token,
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


app.listen(PORT, () => { console.log(`Listening to PORT:${PORT}`) })