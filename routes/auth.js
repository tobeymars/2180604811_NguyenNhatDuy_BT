var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
const  check_authentication  = require('../Utils/check_auth');
let bcrypt = require('bcrypt')

router.post('/signup', async function(req, res, next) {
    try {
        let body = req.body;
        let result = await userController.createUser(
          body.username,
          body.password,
          body.email,
          body.role,
        )
        res.status(200).send({
          success:true,
          data:result
        })
      } catch (error) {
        next(error);
      }

})
router.post('/login', async function(req, res, next) {
    try {
        let username = req.body.username;
        let password = req.body.password;
        let result = await userController.checkLogin(username,password);
        res.status(200).send({
            success:true,
            data:result
        })
      } catch (error) {
        next(error);
      }

})
router.get('/me',check_authentication.check_authentication, async function(req, res, next){
    try {
      res.status(200).send({
        success:true,
        data:req.user
    })
    } catch (error) {
        next();
    }
})

// Chỉ Admin mới được reset mật khẩu
router.get("/resetPassword/:id", 
  check_authentication.check_authentication, 
  check_authentication.check_admin, 
  async (req, res) => {
      try {
        const userId = req.params.id;
        const user = await userController.getUserById(userId);;

          if (!user) {
              return res.status(404).json({ success: false, message: "Người dùng không tồn tại" });
          }

          // Reset password về 123456
          user.password = "123456";
          await user.save();

          return res.status(200).json({ success: true, message: "Đặt lại mật khẩu thành công!" });
      } catch (error) {
          return res.status(500).json({ success: false, message: "Lỗi hệ thống: " + error.message });
      }
  }
);

router.post("/changePassword", check_authentication.check_authentication, async (req, res) => {
  try {
      const { password, newpassword } = req.body;

      // Lấy user từ request sau khi đã xác thực (từ middleware check_authentication)
      const user = req.user;
      if (!user) {
          return res.status(401).json({ success: false, message: "Người dùng chưa đăng nhập" });
      }

      // Kiểm tra password hiện tại có đúng không
      const isMatch = bcrypt.compareSync(password, user.password);
      if (!isMatch) {
          return res.status(400).json({ success: false, message: "Mật khẩu hiện tại không đúng" });
      }
      // Cập nhật mật khẩu mới cho user
      user.password = newpassword;
      await user.save();

      return res.status(200).json({ success: true, message: "Đổi mật khẩu thành công" });
  } catch (error) {
      return res.status(500).json({ success: false, message: "Lỗi hệ thống: " + error.message });
  }
});

module.exports = router