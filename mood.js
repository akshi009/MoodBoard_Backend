import express from 'express'
import mongoose from 'mongoose'
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
        const newuser = new Users({ name, email, password })
        await newuser.save();
        res.status(200).json({ success: true, message: "created sucessfully",newuser })

    } catch (error) {
        console.log(error, 'error in creating user');
        res.status(500).send('Error creating user');
    }

})

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body
        const existinguser = Users.find({ email })
        if (!existinguser) return res.status(400).json({ success: false, message: "User Not Found" });
        res.json({ success: true, message: "Login successful" });

    } catch (error) {
        console.log(error, 'error in Login user');
        res.status(500).send('Error login user');
    }
})

app.listen(PORT, () => { console.log(`Listening to PORT:${PORT}`) })