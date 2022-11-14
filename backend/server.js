const app = require("./app");

const dotenv = require("dotenv");

// Uncaught Exception Error
process.on("uncaughtException", err=>{
    console.log(`Error: ${err.message}`);
    console.log("Shutting down the server due to uncaught exception");
    process.exit(1);
})

const connectDatabase = require("./config/database");

//config
dotenv.config({path:"backend/config/config.env"});

// Connecting Database
connectDatabase();

const server = app.listen(process.env.PORT, ()=>{
    console.log(`Server is listening on http://localhost:${process.env.PORT}`);
})

// Unhandled Promsie Rejection

process.on("unhandledRejection", err => {
    console.log(`Error: ${err.message}`);
    console.log("Shutting down the server due to unhanlded rejection");

    server.close(()=> {
        process.exit(1);
    })
})