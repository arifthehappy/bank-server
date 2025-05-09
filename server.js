const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const authRoutes = require("./routes/auth");

const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS for all routes
app.use(express.urlencoded({ extended: true }));

const port = process.env.PORT || 3001

 
// const { MongoClient, ServerApiVersion } = require('mongodb');
const mongoURI = process.env.MONGO_URI || "mongodb+srv://arifthehappy:hiLIQF6g7CLXJH58@cluster0.5k9fpm9.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

//connect to client using mongoose
mongoose.connect(mongoURI,{
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 10000
})
.then(() => {
  console.log("MongoDB connected successfully");
}
).catch((err) => {
  console.error("MongoDB connection error:", err);
}
);

// basic route
app.get("/", (req, res) => {
  res.send("Hello World!");
});


// use routes
app.use("/auth", authRoutes);
// app.use("/webhooks", webhookListener);



// start server
app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});

module.exports = app;

