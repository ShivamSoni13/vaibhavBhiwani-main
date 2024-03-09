const productModel = require("../models/products/products");
const userModel = require("../models/registerUser/registerUser");
const apiFeatures = require("../utils/apiFeatures");

//post product //admmin
exports.postProducts = async (req, res) => {
  // let {user}=req.body;
  user = req.user; //geting id of login user
  console.log(user);
  try {
    const {
      name,
      price,
      ratings,
      category,
      stock,
      numOfReviews,
      review,
      images,
      reviews,
    } = req.body;
    const response = new productModel({
      name: name,
      price: price,
      ratings: ratings,
      category: category,
      stock: stock,
      numOfReviews: numOfReviews,
      review: review,
      images: images,
      user: user,
      reviews: reviews,
    });
    const result = await response.save();
    res.status(200).json({
      success: true,
      message: "products store sucessfuly in mongodb",
      result: result,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      message: "internal server error",
    });
  }
};

//getALlProducts //All users ;
exports.getAllproducts = async (req, res) => {
  try {
    console.log(req.query);
    //  const api=new apiFeatures(productModel.find({}),req.query);
    const api = new apiFeatures(productModel.find(), req.query)
      .search()
      .filter();
    // const result = await productModel.find({});
    const result = await api.query;

    res.status(200).json({ success: true, result: result });
  } catch (err) {
    res.status(401).json({
      success: false,
      error: err.message,
      message: "products not found",
    });
  }
};
//get single products based on particular id
exports.getSingleProducts = async (req, res) => {
  try {
    const _id = req.params;

    const data = await productModel.findOne({ _id: _id });

    res.status(200).json({ products: data, success: true });
  } catch (error) {
    res.status(400).json({ message: "product not found", success: false });
  }
};

//update the products based on id
exports.updateProducts = async (req, res) => {
  try {
    const _id = req.params._id;
    const {
      name,
      price,
      ratings,
      category,
      stock,
      numOfReviews,
      review,
      images,
    } = req.body;
    const result = await productModel.findByIdAndUpdate(
      { _id: _id },
      {
        name: name,
        price: price,
        ratings: ratings,
        category: category,
        stock: stock,
        numOfReviews: numOfReviews,
        review: review,
        images: images,
      },
      { new: true }
    );
    await result.save();
    res.status(200).json({ success: true, message: "updated successfuly" });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
};

//delete the products api
exports.deleteProduct = async (req, res) => {
  try {
    const { _id } = req.params;
    const data = await productModel.findByIdAndDelete({ _id: _id });
    res.status(200).json({
      message: "product is deleted successfuly",
      success: true,
      result: data,
    });
  } catch (error) {
    res
      .status(400)
      .json({ message: "product not deleted", success: false, error: error });
  }
};

//review and comment controller
exports.reviewSystem = async (req, res) => {
  try {
    const userId = req.user;
    const user = await userModel.findOne({ _id: userId });
    const name = user.name;
    const { rating, comment } = req.body;

    // Find the product by ID
    const findProduct = await productModel.findById(req.params);

    // Check if the product exists
    if (!findProduct) {
      return res.status(404).json({ message: "Product not found" });
    }

    // Check if the user has already provided a review
    const existingReviewIndex = findProduct.reviews.findIndex(
      (review) => review.user.toString() === userId
    );

    // If the user has already provided a review, update it; otherwise, add a new review
    if (existingReviewIndex !== -1) {
      // Update the existing review
      findProduct.reviews[existingReviewIndex].rating = rating;
      findProduct.reviews[existingReviewIndex].Comment = comment;
    } else {
      // Add a new review
      findProduct.reviews.push({
        name: name,
        user: userId,
        rating: rating,
        Comment: comment,
      });
    }

    // Update the overall ratings and noOfReviews for the product
    const totalRatings = findProduct.reviews.reduce (
      (sum, review) => sum + review.rating,
      0
    ) ;
    findProduct.ratings = totalRatings / findProduct.reviews.length;
    findProduct.noOfReviews = findProduct.reviews.length;

    // Save the updated product
    await findProduct.save();

    res.status(200).json({ message: "Review updated successfully" });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
};
