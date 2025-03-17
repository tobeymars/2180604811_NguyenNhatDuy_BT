let jwt = require('jsonwebtoken')
let constants = require('../Utils/constants')
let userController = require('../controllers/users')
module.exports={
    check_authentication: async function(req,res,next){
        if(req.headers.authorization){
            let token_authorization = req.headers.authorization;
            if(token_authorization.startsWith("Bearer")){
              let token = token_authorization.split(" ")[1];
              let verifiedToken = jwt.verify(token,constants.SECRET_KEY);
              if(verifiedToken){
                console.log(verifiedToken);
                let user = await userController.getUserById(
                    verifiedToken.id  
                )
                req.user = user;
                next()
              }
            }else{
              throw new Error("ban chua dang nhap")
            }
          }else{
            throw new Error("ban chua dang nhap")
          }  
    },
    check_admin: async function(req, res, next) {
      try {
          if (!req.user) {
              return res.status(401).json({ success: false, message: "Bạn chưa đăng nhập" });
          }
  
          console.log("User role:", req.user.role); // In ra role để kiểm tra
  
          if (req.user.role && req.user.role.roleName === "Admin") {
              next();
          } else {
              return res.status(403).json({ success: false, message: `Bạn không có quyền Admin. Role hiện tại: ${req.user.role.roleName}` });
          }
      } catch (error) {
          return res.status(500).json({ success: false, message: "Lỗi hệ thống: " + error.message });
      }
  }
  
  
  
  
}