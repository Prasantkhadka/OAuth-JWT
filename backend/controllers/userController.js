import User from "../models/userModel.js";

export const getUserProfile = async (req, res) => {
  try {
    const userId = req.user.id;

    const user = await User.findById(userId).select(
      "-password -__v -verifyOtp -verifyOtpExpiry -resetOtp -resetOtpExpiry"
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // map backend field `isAccountVerified` to a friendly `isVerified` for the frontend
    const userObj = {
      id: user._id,
      name: user.name,
      email: user.email,
      isVerified: !!user.isAccountVerified,
    };

    return res.status(200).json({ user: userObj });
  } catch (error) {
    return res.status(500).json({
      message: "Server error in getUserData",
      error: error.message,
    });
  }
};
