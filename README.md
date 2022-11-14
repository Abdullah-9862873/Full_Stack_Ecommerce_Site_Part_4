# Full_Stack_Ecommerce_Site_Part_4
**Step 1:** Make two folders "frontend" and "backend"

**Step 2:** Inside backend create two files "app.js" and "server.js"

**Step 3:** Inside root directory open a terminal and type command, "npm init" and inside the entry point, type "backend/server.js"

**Step 4:** Install the packages "npm install mongoose express dotenv"

**Step 5:** Install the package "npm install nodemon"

**Step 6:** Setup the app.js file as
```

			const express = require("express");

			const app = express();

			module.exports = app;
```

**Step 7:** Setup the server.js file as
```
			const app = require("./app");

			app.listen(process.env.PORT, ()=>{
			    console.log(`Server is listening on http://localhost:${process.env.PORT}`);
			})
```
**Step 8:** Make a folder inside "backend" by the name "config" and inside config, make a file "config.env" and inside config.env type
```
			PORT=4000
```
**Step 9:** Import dotenv in "server.js" file as:
```
			const dotenv = require("dotenv")
			dotenv.config({path:"backend/config/config.env"})
```
**Step 10:** Add the following inside the "package.json" file, inside the "script" and here if we run start then it will open it in using node and if we run dev then it will open it using nodemon and we will use dev in the development mode but in the production mode we use node
```
			    "start": "node backend/server.js",
			    "dev": "nodemon backend/server.js"
```
**Step 11:** Make two folders inside the "backend" named "routes" and "controllers"

**Step 12:** Inside the "routes" make a new file "productRoute.js" and inside the "controllers", make a new file named "productController.js"

**Step 13:** Inside the "productController.js", type the following
```
			exports.getAllProducts = (req, res) => {
 			   res.status(200).json({message: "route is working fine"});
			}
```
**Step 14:** Inside the "productRoute.js", type the following
```
			const express = require("express");
			const { getAllProducts } = require("../controllers/productController");

			const router = express.Router();

			router.route("/products").get(getAllProducts);

			module.exports = router;
```
**Step 15:** Import the Route in your "app.js" file  and now your app.js file will look like the following:
```
			const express = require("express");
			const app = express();

			app.use(express.json());

			// Route Import
			const product = require("./routes/productRoute");

			app.use("/api/v1",product)

			module.exports = app;
```			
**Step 16:** Now open the terminal and run the app in the dev mode by
```
			npm run dev
```
**Step 17:** Now go to the postman and make a new Collection named "Ecommerce"... Now click on the + option at the top left and make a get request to 
			http://localhost:4000/api/v1/products

	You'll see the message on the screen inside the postman that "server is working fine"

## Connecting Database

**Step 18:** Create a folder inside "config", named "database.js"

**Step 19:** Write the following code inside "database.js"
```
			const mongoose = require("mongoose");


			const connectDatabase = ()=>{
			    mongoose.connect(process.env.DB_URI).then((data)=>{
			        console.log(`MongoDB connected with server: ${data.connection.host}`);
			    }).catch((err)=>{
			            console.log(err);
			        })
			}

			module.exports = connectDatabase;

```
**Step 20:** Import the database inside the "server.js"
```
			const connectDatabase = require("./config/database");
```
**Step 21:** Run the connectDatabase function
```
			connectDatabase();
```
## models

**Step 22:** Make a new folder named "models" inside "backend" folder.

**Step 23:** Make a new file named "productModel.js" inside "models"

**Step 24:** Make a product Schema inside "productModels.js"
```
			const mongoose = require("mongoose");

			const productSchema = new mongoose.Schema({
			    name: {
			        type:String,
			        required:[true, "Please enter the name of product"],
			        trim:true
			    },
			    description: {
			        type: String,
			        required:[true, "Please enter the description of product"]
			    },
			    price: {
			        type: Number,
			        required:[true, "Please enter the price of product"],
			        maxLength:[8, "Price cannot exceed 8 characters"]
			    },
			    rating: {
			        type: Number,
			        default:0
			    },
			    images: [
			        {
			            public_id: {
			                type:String,
			                required:true
			            },
			            url: {
			                type:String,
			                required: true
			            }
			        }
			    ],
			    category: {
			        type: String,
			        required:[true, "Please enter product category"]
			    },
			    Stock: {
			        type: Number,
			        required: [true, "Please enter product stock"],
			        maxLength: [4, "Stock length cannot exceed 4 characters"],
			        default: 1
			    },
			    numOfReviews: {
			        type: Number,
			        default: 0
			    },
			    reviews: [
			        {
			            name: {
			                type: String,
			                required: true
			            },
			            rating: {
			                type: Number,
			                required: true
			            },
			            comment: {
			                type: String,
			                required: true
			            }
			        }
			    ],
			    createdAt: {
			        type: Date,
			        default: Date.now
			    }
			})

			module.exports = mongoose.model("Product", productSchema);
```
## createProduct

**Step 25:** Go to the "productController.js" inside "controllers" and type the following
```
				// Create Product --- Admin

				exports.createProduct = async (req, res, next)=> {
				    const product = await Product.create(req.body);

				    res.status(201).json({
				        success: true,
				        product
				    })
				}
```
**Step 26:** Now the "productController.js" will be something like
```
				const Product = require("../models/productModel");

				// Create Product --- Admin

				exports.createProduct = async (req, res, next)=> {
				    const product = await Product.create(req.body);
				
				    res.status(201).json({
				        success: true,
			        product
			    })
			}


				// Get All Products
				exports.getAllProducts = async (req, res) => {
				    const products = await Product.find();
			
				    res.status(200).json(
				        {
				            success: true,
				            products
				        }
				    )
				}
```
**Step 27:** Add a new router inside "productRoute.js" 
```
				router.route("/product/new").post(createProduct);
```

## Update Product

**Step 28:** Add the following in "productController.js" 
```
				// Update Product --- Admin

				exports.updateProduct = async (req, res, next) => {
				    let product = Product.findById(req.params.id);
				
				    if(!product){
				        return res.status(500).json({
				            success:false,
				            message: "Product not found"
				        })
				    }

				    product = await Product.findByIdAndUpdate(req.params.id, req.body,
			        {
			            new: true,
			            runValidators: true,
			            userFindandModify: false
				})

				    res.status(200).json({
				        success: true,
				        product
				    })
				}
```
## Delete Product

**Step 29:** Add the following in "productController.js" 
```
				// Delete Product --- Admin

				exports.deleteProduct = async (req, res, next) => {
				    const product = await Product.findById(req.params.id);
		
				    if(!product){
				        return res.status(500).json({
				            success:false,
				            message: "Product not found"
				        })
				    }
		
				    await product.remove();
			
				    res.status(200).json({
				        success: true,
				        message: "Product Deleted successfully"
				    })
				}
```
## Get Product Details

**Step 30:** Inside the "productController.js" type the following
```

				// Get Product Details
				exports.getProductDetails = async (req, res, next)=>{
				    const product = await Product.findById(req.params.id);

				    if(!product){
				        res.status(500).json({
				            success: false,
				            message: "Product not found"
				        })
				    }
			
				    res.status(200).json({
				        success: true,
				        product
				    })
				}
```
**Step 31:** Add the routes of the above insde the "productRoute.js" as
```				
				router.route("/products").get(getAllProducts);
				router.route("/product/new").post(createProduct);
				router.route("/product/:id").put(updateProduct).delete(deleteProduct).get(getProductDetails);
```
## Error Handling

**Step 32:** Make a folder named "utils" inside the "backend" folder and make a file named "errorhandler.js" inside it

**Step 33:** Type the following inside the file
```
				class ErrorHandler extends Error{
   				 constructor(message, statusCode){
				        super(message);
				        this.statusCode = statusCode;

				        Error.captureStackTrace(this, this.constructor);
				    }
				}

				module.exports = ErrorHandler;
```
**Step 34:** Make a new folder named "middleware" inside the backend and make a new file named "error.js" inside it

**Step 35:** Type the following inside the "error.js" file
```
				const ErrorHandler = require("../utils/errorhandler");

				module.exports = (err, req, res, next) => {
				    err.statusCode = err.statusCode || "500";
				    err.message = err.message || "Internal Server Error";
	
				    res.status(err.statusCode).json({
				        success: false,
				        message: err.messages
				    })
				}
```
**Step 36:** Import the errorMiddleware inside the "app.js"
```
				const errorMiddleware = require("./middleware/error");
```
**Step 37:** Use the errorMiddleware inside the "app.js"... Remember to use it below "app.use("/api/v1",product)".
```
				app.use(errorMiddleware);
```
**Step 38:** Now you can go to the "productController.js" and update the files for example the "Get Product Details" will look like the following. But you have to import it to the "productController.js" file.
```
				const ErrorHandler = require("../utils/errorhandler");
				// Get Product Details
				exports.getProductDetails = async (req, res, next)=>{
				    const product = await Product.findById(req.params.id);

				    if(!product){
				        return next(new ErrorHandler("Product not Found", 404));
				    }
		
				    res.status(200).json({
				        success: true,
			        	product
				    })
				}
```
	Now if you don't give a valid product id while finding it or getting it then it will display the error accordingly

## Handling Async Errors

It is a good practice to write .then and .catch inside async await functions. To avoid writing .then and .catch again and again inside the product controller we'll make an error handler for it

**Step 39:** Make a new file inside the "middleware" named "catchAsynErrors.js" and add the following code into it.
```
				const catchAsyncErrors = theFunc => (req, res, next) => {
				    Promise.resolve(theFunc(req, res, next)).catch(next);
				}

				module.exports = catchAsyncErrors;
```			
**step 40:** Import it inside "productController.js".
```
				const catchAsyncErrors = require("../middleware/catchAsyncErrors");
```
**Step 41:** Now update the "productController.js".
```

	const Product = require("../models/productModel");
	const ErrorHandler = require("../utils/errorhandler");
	const catchAsyncErrors = require("../middleware/catchAsyncErrors");

	// Create Product --- Admin

	exports.createProduct = catchAsyncErrors(async (req, res, next)=> {
	    const product = await Product.create(req.body);

	    res.status(201).json({
	        success: true,
	        product
	    })
	});

	// Update Product --- Admin

	exports.updateProduct = catchAsyncErrors(async (req, res, next) => {
	    let product = Product.findById(req.params.id);

	    if(!product){
	        return res.status(500).json({
	            success:false,
	            message: "Product not found"
	        })
	    }
	
	    product = await Product.findByIdAndUpdate(req.params.id, req.body,
	        {
	            new: true,
	            runValidators: true,
	            userFindandModify: false
	        })
	
	    res.status(200).json({
	        success: true,
	        product
	    })	
	});
	
	// Delete Product --- Admin
	
	exports.deleteProduct = catchAsyncErrors(async (req, res, next) => {
	    const product = await Product.findById(req.params.id);
	
	    if(!product){
	        return res.status(500).json({
	            success:false,
        	    message: "Product not found"
	        })
	    }
	
	    await product.remove();
	
	    res.status(200).json({
	        success: true,
	        message: "Product Deleted successfully"
	    })
	});
	
	// Get Product Details
	exports.getProductDetails = catchAsyncErrors(async (req, res, next)=>{
	    const product = await Product.findById(req.params.id);
	
	    if(!product){
	        return next(new ErrorHandler("Product not Found", 404));
	    }
	
	    res.status(200).json({
	        success: true,
	        product
	    })
	});
	
	// Get All Products
	exports.getAllProducts = catchAsyncErrors(async (req, res) => {
	    const products = await Product.find();
	
	    res.status(200).json(
	        {
	            success: true,
	            products
	        }
	    )
	});
```	
Now if you don't type the name or any required field while creating the product then it won't crash the server rather it will display the error

## Unhandled Promise Rejection


If we change the "DB_URI"  inside the "config.env" file to "mongodb://localhost:27017/Ecommerce" then it will throw an error and to resolve this we can make the following changes inside the "server.js"
We have to crash the Server 

**Step 42:** Inside the "server.js" update the app.listen to the following
```
	const server = app.listen(process.env.PORT, ()=>{
	    console.log(`Server is listening on http://localhost:${process.env.PORT}`);
	})
```
**Step 43:** Inside the "server.js" write the following code at the end
```
	// Unhandled Promsie Rejection

	process.on("unhandledRejection", err => {
	    console.log(`Error: ${err.message}`);
	    console.log("Shutting down the server due to unhanlded rejection");

	server.close(()=> {
        	process.exit(1);
	    })
	})
```
**Step 44:** Now you can remove the ".catch" method inside "database.js" and your " database.js" will look like.
```
	const mongoose = require("mongoose");

	const connectDatabase = ()=>{
	    mongoose.connect(process.env.DB_URI).then((data)=>{
	        console.log(`MongoDB connected with server: ${data.connection.host}`);
	    })
	}

	module.exports = connectDatabase;
```
## Handling Uncaught Exception

If you type "console.log(youtube)" in your "server.js" then it will throw an error which says "youtube is not defined". These type of errors are called uncaught errors.

**Step 45:** Inside the "server.js" file at the top of the file, type the following code
```
	// Uncaught Exception Error
	process.on("uncaughtException", err=>{
	    console.log(`Error: ${err.message}`);
	    console.log("Shutting down the server due to uncaught exception");
	    process.exit(1);
	})
```
## Handling Cast Error Mongodb
**Step 46:** If you give the less or more number of characters in the id then it will show you a cast error and to handle this error we can write the following code inside the "errorhandler.js" just below the line "err.message = err.message || "Internal Server Error";"
```
	// Mongodb Cast Error Handler
	    if(err.name === "CastError"){
	        const message = `Resource not found. Invalid ${err.path}`;
	        err = new ErrorHandler(message, 400);
	    }
```
## Searching Products by Name
**Step 47:** Make a new file inside "utils" named "apifeatures.js" and add the following code into it.
```
	class ApiFeatures {
	    constructor(query, queryStr){
	        this.query = query;
	        this.queryStr = queryStr;
	    }

	    search(){
	        const keyword = this.queryStr.keyword ? {
	            // Got the keyword
	            name: {
	                // We are searching for the name of the product
	                $regex: this.queryStr.keyword,
	                $options : "i",
	            },
	        } : {};
	
	        this.query = this.query.find({...keyword});
	        return this;
	    }
	}
	
	module.exports = ApiFeatures;
```
**Step 48:** Update the "getAllProducts" section of "productController.js".
```
	// Get All Products
	exports.getAllProducts = catchAsyncErrors(async (req, res) => {
	    const apiFeature = new ApiFeatures(Product.find(), req.query).search();
	    const products = await apiFeature.query;

	    res.status(200).json(
	        {
        	    success: true,
	            products
	        }
	    )
	});
```
## Adding filter Section
**Step 49:** Add the following object below the search() object inside "ApiFeatures" class inside "apifeatures.js".
```
	    filter(){
	        const queryCopy = {...this.queryStr};
	        // Removing some fields for category
        	const removeFields = ["keyword", "page", "limit"];
	        removeFields.forEach(key=> {
	            delete queryCopy[key];
	        })

	        this.query = this.query.find(queryCopy);
	        return this;
	    }
```

Here we have made the copy of queryStr first and then stored the copy inside the queryCopy because we do not want to alter the real queryStr.
Also, the queryStr is an object which is {"category" : "something"} so no need to pass the queryCopy as an object inside this.query.find()
Also, this is case Sensitive so a category of "Laptop" will be searched as a "Laptop" only

**Step 50:** Update the "getAllProducts" of "productController.js".
```
	// Get All Products
	exports.getAllProducts = catchAsyncErrors(async (req, res) => {
	    const apiFeature = new ApiFeatures(Product.find(), req.query).search().filter();
	    const products = await apiFeature.query;
	
	    res.status(200).json(
	        {
	            success: true,
	            products
	        }
	    )
	});
```
## Filter for pricing and Rating

**Step 51:** To add the pricing and rating, update the filter() inisde the "apifeatures.js" as.
```
	filter(){
	        const queryCopy = {...this.queryStr};
	        // Removing some fields for category
	        const removeFields = ["keyword", "page", "limit"];
	        removeFields.forEach((key)=> {
	            delete queryCopy[key];
	        })
	
	        // Filter for pricing and rating
	        let queryStr = JSON.stringify(queryCopy);
	        queryStr = queryStr.replace(/\b(gt|lt|gte|lte)\b/g, key => `$${key}`);

	        this.query = this.query.find(JSON.parse(queryStr));
	        return this;
	    }
```

Now you can go to the postman and type the following
```
			KEY				VALUE
			keyword				product
			category			Laptop
			price[gt]			1200
			price[lt]			2000
```
And this will filter the products for you

## Pagination
**Step 52:** Make the following changes inside **"getAllProducts"** inside **"productController.js"**
```

exports.getAllProducts = catchAsyncErrors(async (req, res) => {
    const resultPerPage = 5;
    const apiFeature = new ApiFeatures(Product.find(), req.query).search().filter().pagination(resultPerPage);
    const products = await apiFeature.query;

    res.status(200).json(
        {
            success: true,
            products
        }
    )
});
```
**Step 53:** Write the following code inside the **"ApiFeatures"** class inside **"apifeatures.js"**
```
    pagination(resultPerPage){
        const currentPage = this.queryStr.page;
        const skip = resultPerPage * (currentPage - 1);

        this.query = this.query.limit(resultPerPage).skip(skip);
        return this;
    }
```
**currentPage** is the page where the user is, and **skip** is the number of objects to skip. Now you can create 10 products inside the **"create Product"** inside Postman and give the following inside **"KEY"** and **"VALUE"**

**Step 54:** Inside the "getAllProducts" section in "productController.js" write the following code below the "const resultPerPage = 5;"
```
			const productCount = await Product.countDocuments();
```

Also add the "productCount" as JSON in "getProductDetails" and update the "getProductDetails" as
```
	// Get Product Details
	exports.getProductDetails = catchAsyncErrors(async (req, res, next)=>{
	    const product = await Product.findById(req.params.id);
	
	    if(!product){
	        return next(new ErrorHandler("Product not Found", 404));
	    }
	
	    res.status(200).json({
        	success: true,
	        product,
	        productCount
	    })
	});
```

## Backend User and Password Authentication

**Step 55:** Open the terminal and add the following packages into your workplace
```
			npm install bcryptjs jsonwebtoken validator nodemailer cookie-parser body-parser
```

**bcrypt:** is used to hash the passwords of users\
**validator:** is used to validate the user has entered the email and nothing else in the email section\
**nodemailer:** is used to send the OTP\
**cookie-parser:** is used to store the jsonwebtoken inside cookies\


**Step 56:** Inside the **"models"** folder. Make a new file named **"userModel.js"** and type the following code in it
```
	const mongoose = require("mongoose");
	const validator = require("validator");

	const userSchema = new mongoose.Schema({
	    name: {
	        type: String,
	        required: [true, "Please Enter your Name"],
	        maxLength: [30, "Name cannot exceed 30 characters"],
	        minLength: [4, "Name should have more than 4 characters"]
	    },
	    email: {
	        type: String,
	        required: [true, "Please Enter your Email"],
        	unique:true,
	        validate: [validator.isEmail, "Please Enter a valid Email"]
	    },
	    password: {
        	type: String,
	        required: [true, "Please Enter your Password"],
        	select: false,
	        minLength: [8, "Password should have more than 8 characters"]   
	    },	
	    avatar: {
	        public_id: {
        	    type: String,
	            required: true
	        },
	        url: {
	            type: String,
	            required: true
	        }
	    },
	    role: {
	        type: String,
        	default: "user"
	    },
	
	    resetPasswordToken: String,
	    restPasswordExpire: Date,
	})

	module.exports = mongoose.model("User",userSchema);
```

## Register a User
**Step 57:** Make a new file named **"userController.js"** inside **"controllers"**

```
		const ErrorHandler = require("../utils/errorhandler");
	const catchAsyncErrors = require("../middleware/catchAsyncErrors");
	const User = require("../models/userModel");

	// Register a User
	exports.registerUser = catchAsyncErrors(async (req, res, next) => {
	    const {name, email, password} = req.body;
	
	    const user = await User.create({
	        name, email,password, 
	        avatar: {
	            public_id: "This is a sample id",
	            url: "This is a sample url"
	        },
	    });
	
	    res.status(201).json({
	        success: true,
	        user
	    })
	})
```

**Step 58:** Make a new file named **"userRoute.js"** inside **"routes"** folder inside **"backend"**. Add the following code into it
```
	const express = require("express");
	const { registerUser } = require("../controllers/userController");

	const router = express.Router();

	router.route("/register").post(registerUser);

	module.exports = router;
```

**Step 59:** Go to the **"app.js"** file and add the following code below where the **"product"** route is imported
```
			const user = require("./routes/userRoute");
```

And add the following code into the same file below the **app.use("/api/v1",product)**
```
			app.use("/api/v1",user)
```

Now your **"app.js"** will look something like this
```
	const express = require("express");
	const app = express();
	const errorMiddleware = require("./middleware/error");

	app.use(express.json());

	// Route Import
	const product = require("./routes/productRoute");
	const user = require("./routes/userRoute");

	app.use("/api/v1",product)
	app.use("/api/v1", user)

	// Middleware for Errors

	app.use(errorMiddleware);

	module.exports = app;
```
## Hashing the Password
**Step 60:** Go to the **"userModel.js"** inside **"models"** and add the following code at the top:
```
			const bcrypt = require("bcryptjs")
```
**Step 61:** In the same file, above the *module.exports = mongoose.model("User",userSchema);* add the following code:
```
	userSchema.pre("save", async function(next){

	    if(!this.isModified("password")){
        	next();
	    }

	    this.password = await bcrypt.hash(this.password,10);
	})
```
In this code we have used **function** rather than a callback function and the reason is that we can use *this* inside the **function** but cannot use it inside **callback** function
*If* condition is showing that if the password is modified by the user then only hash it othervise leave it and in this way we'll save the code from hashing the hashed passwords.

**Step 62:** Go to the file **"userModel.js"** inside **"models"** folder and import the following
```
			const jwt = require("jsonwebtoken");
```

**Step 63:** In the same file type the following code at the end of the file just above *module.exports = mongoose.model("User",userSchema);*
```
	// JWT Token
	userSchema.methods.getJWTToken = function(){
	    return jwt.sign({id: this._id}, process.env.JWT_SECRET, {
	        expiresIn: process.env.JWT_EXPIRE,
	    });
	}
```

**Step 64:** Go to the **"config.env"** file inside the folder **"config"** and add the following into it
```
			JWT_SECRET=kajdsfjkasdfklhsdkfhkasdhfkasdfk
			JWT_EXPIRE=5d
```

**Step 65:** Go to the file **"userController.js"** inside the **"controllers"** folder and update the *res.status* inside the *Register the User*. The code for *Register the User* will look like
```
	// Register a User
	exports.registerUser = catchAsyncErrors(async (req, res, next) => {
	    const {name, email, password} = req.body;

	    const user = await User.create({
	        name, email,password, 
	        avatar: {
	            public_id: "This is a sample id",
	            url: "This is a sample url"
	        },
	    });

	    const token = user.getJWTToken();

	    res.status(201).json({
	        success: true,
	        token
	    })
	})
```
Now when you create a user using Post request inside the postman then it will not show the user rather it will show you the token generated for that user

## Login User
**Step 66:** Go to the **"userController.js"** file inside the folder **"controllers"** and add the following code at the end of file
```
	// Login User
	exports.loginUser = catchAsyncErrors(async (req, res, next) => {
	    const {email, password} = req.body;

	    // Check if the user has entered Email and Password both
	    if(!email || !password){
	        next(new ErrorHandler("Please Enter Email & Password", 400));
	    }
	
	    const user = await User.findOne({email}).select("+password");
	
	    if(!user){
	        next(new ErrorHandler("Invalid email or password", 401));
	    }
	
	    const isPasswordMatched = user.comparePassword(password);
	
	    if(!user){
	        next(new ErrorHandler("Invalid email or password", 401));
	    }
	
	    const token = user.getJWTToken();
	
	    res.status(200).json({
	        success: true,
	        token
	    })
	})
```

*400*: Bad Request Error\
*401*: Unautorized\

In this code ***.select("+password")*** is used because while creating the user Model we have make the password to ***select false*** so here we have to mannually select it\
First we check if the user is present and then we get the password and compare it with the database\

**Step 67:** Go to the **"userModel.js"** inside the folder **"models"** and type the following code above the *module.exports = mongoose.model("User",userSchema);*
```
	// Compare Password
	userSchema.methods.comparePassword = function(enteredPassword){
	    return bcrypt.compare(enteredPassword, this.password);
	}
```

**Step 68:** Go to the **"userRoute.js"** inside the folder **"routes"** and add the following route into it
```
				router.route("/login").post(loginUser);
```
Also you have to import the *loginUser* like
```
	const { registerUser, loginUser } = require("../controllers/userController");
```

**Step 67:** Now you don't have to write the following code again and again in the userController.js
```
	    const token = user.getJWTToken();

    		res.status(200).json({
	        	success: true,
	        	token
		    })
```

Rather make a new file named **"jwtToken.js"** in the **"utils"** folder and write the following code in it
```
		// Creating Token and Saving in cookie

	const sendToken = (user, statusCode, res)=>{
	    const token = user.getJWTToken();
	
	    // options for cookie
	    const options = {
	        expire: new Date(
	            Date.now() + process.env.COOKIE_EXPIRE *24*60*60*1000
	        ),
	        httpsOnly:true,
	    };
	    res.status(statusCode).cookie("token",token, options).json({
	        success:true,
	        user,
	        token
	    })
	}

	module.exports = sendToken;
```

Now go to the **"userController.js"** file in the **"controllers"** folder and import it first by
```
		const sendToken = require("../utils/jwtToken");
```

After importing replace the upper code from **"Register the user"** to the following
```
		sendToken(user, 201, res);
```

And replace the upper code from **"Login User"** to the following 
```
		sendToken(user,200, res);
```

Now the final **"userController.js"** will look like
```
const ErrorHandler = require("../utils/errorhandler");
const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const User = require("../models/userModel");
const sendToken = require("../utils/jwtToken");

// Register the User
exports.registerUser = catchAsyncErrors(async (req, res, next) => {
    const {name, email, password} = req.body;

    const user = await User.create({
        name, email,password, 
        avatar: {
            public_id: "This is a sample id",
            url: "This is a sample url"
        },
    });

    sendToken(user, 201, res);
});

// Login User
exports.loginUser = catchAsyncErrors(async (req, res, next) => {
    const {email, password} = req.body;

    // Check if the user has entered Email and Password both
    if(!email || !password){
        next(new ErrorHandler("Please Enter Email & Password", 400));
    }

    const user = await User.findOne({email}).select("+password");

    if(!user){
        next(new ErrorHandler("Invalid email or password", 401));
    }

    const isPasswordMatched = user.comparePassword(password);

    if(!user){
        next(new ErrorHandler("Invalid email or password", 401));
    }

    sendToken(user,200, res);
})
```
**Step 68:** Add the following into the **"config.env"** file inside the "config" folder"
```
	COOKIE_EXPIRE=5
```
Now when you send the ***Login User*** request in postman then it will show you the results in body and cookie in cookie

**Step 69:** To make the logged in user, access something let's say "getAllProducts", we make a new file named **"auth.js"** inside **"middleware"** folder and write the following code in it
```
	const catchAsyncErrors = require("./catchAsyncErrors");

	exports.isAuthenticatedUser = catchAsyncErrors(async(req, res, next)=> {
	    const token = req.cookies;
	    console.log(token);    
	})
```
Now go to the **"productRoute.js"** and import the *isAuthenticatedUser* as:
```
			const { isAuthenticatedUser } = require("../middleware/auth");
```
Now update the products route into the following
```
			router.route("/products").get(isAuthenticatedUser, getAllProducts);
```

**Step 70:** Now go to the **"app.js"** and add the following code below the ***app.use(express.json())***
```
			const cookieParser = require("cookie-parser");
```

Now you can go to the postman and go to the getProductDetails and send the Get Request and this will print the token in the console

**Step 71:** Completion of **"auth.js"** is in the following
```
	const jwt = require("jsonwebtoken");
	const ErrorHandler = require("../utils/errorhandler");
	const catchAsyncErrors = require("./catchAsyncErrors");
	const User = require("../models/userModel");
	
	exports.isAuthenticatedUser = catchAsyncErrors(async(req, res, next)=> {
	    const {token} = req.cookies;
	    
	    if(!token){
	        next(new ErrorHandler("Please login to access this resource", 401));
	    }
	
	    const decodedData = jwt.verify(token, process.env.JWT_SECRET);
	
	    req.user = await User.findById(decodedData.id);
	    next();
	})
```
*{token}* gives the value of token in the console but the *token* gives the output like ***{"token": "value"}***\
*jwt.verify* is used to verify that the token and the JWT_SECRET is present and authentic or not.\
The *id* in decodedData is coming from the id that it got while making the *JWT Token* in the *userModel.js*\

## Logout User
**Step 72:** Go to the ***"userController.js"*** and add the following code at the end of the file
```
	// Logout User

	exports.logout = catchAsyncErrors(async (req, res, next)=> {
	    res.cookie("token", null, {
	        expires: new Date(Date.now()),
	        httpOnly: true,
	    });
	
	    res.status(200).json({
	        success: true,
	        message: "Logged Out"
	    })
	})
```

Now go to the ***"userRouter.js"*** and add the following route into it
```
	router.route("/logout").get(logout);
```

You also have to import it inside the ***"userRouter.js"*** as
```
	const { registerUser, loginUser, logout } = require("../controllers/userController");
```

Now if you go to the postman and make a new file with a get request named "Logout User" and you run it... \
This will make the cookie to be null and thus the user is logged out.\
Now if you make a get request on ***"getAllProducts"*** inside postman then this will not show you the products\

**Step 73:** To make the website secure, go to the ***"productRoute.js"*** and add the **isAuthenticatedUser** inside ***"update and delete"*** thus the total code will look like
```
	const express = require("express");
const { getAllProducts, createProduct, updateProduct, deleteProduct, getProductDetails } = require("../controllers/productController");
const { isAuthenticatedUser } = require("../middleware/auth");

const router = express.Router();

router.route("/products").get(isAuthenticatedUser, getAllProducts);
router.route("/product/new").post(isAuthenticatedUser, createProduct);
router.route("/product/:id").put(isAuthenticatedUser, updateProduct).delete(isAuthenticatedUser, deleteProduct).get(getProductDetails);

module.exports = router;
```

**Step 74:** To make the admin only to getProductDetails we have to make some changes inside **"auth.js"**. Go to the **"auth.js"** inside **"middleware"** folder and add the following code at the end of it
```
// Authorize Roles
exports.authorizeRoles = (...roles)=>{
    return (req, res, next) => {
        if(!roles.includes(req.user.role)){
            return next(
                new ErrorHandler(`Role: ${req.user.role} is not allowed to access this resource`, 403)
            )
        }

        next();
    }
}
```
\
***403:*** shows that server know what you are doing but it is rejecting the access\

**Step 75:** Go to the **"productRoute.js"** inside the **'routes"** folder and update the ***router.route("/products")*** as
```
	router.route("/products").get(isAuthenticatedUser, authorizeRoles("admin"), getAllProducts);
```

Now if you go to the postman and get the product details after loggin in then it will decline it.\
As the role of the user inside the database is "user"\
If you change it inside "MongoDB" to ***admin*** then you can access the products

**Step 76:** To make the confusion between the admins to minimum that which admin has created a user.\
Go to the ***"productModel.js"*** and add the following code just above the ***cretedAt*** at the bottom
```
    user: {
        type:mongoose.Schema.ObjectId,
        required:true,
        ref: "User"
    },
```

Now go to the ***"productController.js"*** where we made the "createProduct" and update the ***createProduct*** as:
```
// Create Product --- Admin

exports.createProduct = catchAsyncErrors(async (req, res, next)=> {
    req.body.user = req.user.id;

    const product = await Product.create(req.body);

    res.status(201).json({
        success: true,
        product
    })
});
```

Here ***req.body.user*** will give us the user and we'll assign it to the value of id. Remember when we created Login function then we assigned the user an id\
This is that id.

## Password Reset or Forget

**Step 77:** Go to the ***"userModel.js"*** and add the following code into it just above the ***module.exports = mongoose.model("User",userSchema);***:
```
// Generating Password Reset Token
userSchema.methods.getResetPasswordToken = function(){

    // Generating Token
    const resetToken = crypto.randomBytes(20).toString("hex");

    // Hashing and adding resetPasswordToken to userSchema
    this.resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    // Token Expire Time
    this.restPasswordExpire = Date.now() + 15 *60 * 1000;

    return resetToken;
}
```
**Step 78:** Go to the **"userController.js"** and add the following code into it at the end\
```
// Forget Password
exports.forgotPassword = catchAsyncErrors(async (req, res, next)=>{
    const user = await User.findOne({email: req.body.email});

    if(!user){
        return next(new ErrorHandler("User not found", 404));
    }

    // Get Passowrd Token
    const resetToken = user.getResetPasswordToken();

    await user.save({validateBeforeSave: false})

    // Creating a link to send through the mail
    const resetPasswordUrl = `${req.protocol}://${req.get("host")}/api/v1/password/reset/${resetToken}`;

    const message = `Your password reset token is :- \n\n ${resetPasswordUrl} \n\n If you don't have requested to reset your password then please ignore it`;

    try{
        await sendEmail({
            email: user.email,
            subject: `Ecommerce Password Recovery`,
            message: message,
        })

        res.status(200).json({
            success:true,
            message: `Email sent to ${user.email} successfully`
        })
    }catch(error){
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        await user.save({validateBeforeSave: false});

        return next(new ErrorHandler(error.message, 500));
    }
})
```

Here we have saved the resetPasswordToken and resetPasswordExpire to database, so we have to set them undefined\
Also we have to save the user again after it\
You have to import the ***sendEmail*** into ***userController.js*** by
```
const sendEmail = require("../utils/sendEmail");
```

**Step 79:** Now make a new file named **"sendEmail.js"** inside the **"utils"** folder and add the following code into it

```
const nodeMailer = require("nodemailer");

const sendEmail = async (options) => {
    const transporter = nodeMailer.createTransport({
        host: process.env.SMPT_HOST,
        port: process.env.SMPT_PORT,
        secure:true,
        service: process.env.SMPT_SERVICE,
        auth: {
            user: process.env.SMPT_MAIL,
            pass: process.env.SMPT_PASSWORD,
        }
    })

    const mailOptions = {
        from: process.env.SMPT_MAIL,
        to: options.email,
        subject: options.subject,
        text: options.message,
    }

    await transporter.sendMail(mailOptions);
}

module.exports = sendEmail;
```

**Step 80:** Now go to the ***"config.env"*** and add the following things inside 
```
SMPT_SERVICE=gmail
SMPT_MAIL= mymailforproject12@gmail.com
SMPT_PASSWORD= "gvuzknqyxqtzajhy"
SMPT_HOST= "smpt.gmail.com"
SMPT_PORT= 465
```

***SMPT_PASSWORD*** is actually not my mail password. \
It's the password that I set inside the app password after enabling 2 factor authentication for this mail account\
Now you can go to the ***postman*** and make a ***POST*** request with the address ***http://localhost:4000/api/v1/password/forgot*** and add the following inside **body** -> **raw** -> **JSON**
```
{
    "email": "ag2@youtube.com"
}
```
\n
Now go to the mail and go to the ***sent*** section and you'll see that the mail with a token has been sent to the required user...\
