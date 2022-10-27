let jwtService = require("../services/jwt.service");
let UsersRepository = require('../repositories/user.repository');
const bcrypt = require("bcrypt");
jwtService = new jwtService();
UsersRepository = new UsersRepository();

module.exports = async (req,res,next)=>{    
    try {
        // const accessToken = req.cookies['accessToken'];
        const accessToken = req.headers.accesstoken
        if(accessToken == undefined){res.status(400).send(req.headers.accesstoken)}
        // AccessToken 만료 여부 확인
        // const accessTokenValidation = await jwtService.validateAccessToken(accessToken.split(' ')[1]);
        const accessTokenValidation = await jwtService.validateAccessToken(accessToken);
        const userId = accessTokenValidation.id;
        // AccessToken 만료 시 RefreshToken을 검증하여 AccessToken 재발급
        if(!accessTokenValidation){
            // console.log('AccessToken 만료, 재발급 시작');
            // const refreshToken = req.cookies['refreshToken'];
            const refreshToken = req.headers.refreshtoken
            // RefreshToken 유효기간 확인
            // const refreshTokenValidation = await jwtService.validateRefreshToken(refreshToken.split(' ')[1]);
            const refreshTokenValidation = await jwtService.validateRefreshToken(refreshToken);
            // RefreshToken 만료인 경우 재로그인(RefreshToken 재발급) 
            if(!refreshTokenValidation){ return res.status(403).send({errorMessage: '다시 로그인 해주시길 바랍니다.', }) }
            
            // DB에 저장된 RefreshToken 과 비교하여 위변조 여부 확인
            const findUser = await UsersRepository.findOneById(userId);
            // const compareRefreshToken = bcrypt.compareSync(refreshToken.split(' ')[1],findUser.refreshToken);
            const compareRefreshToken = bcrypt.compareSync(refreshToken,findUser.refreshToken);
            if(!compareRefreshToken){ return res.status(403).send({errorMessage: '다시 로그인 해주시길 바랍니다.', }) }
            
            // AccessToken 재발급
            const newAccessToken = await jwtService.createAccessToken(userId);
            // res.cookie('accessToken', `Bearer ${newAccessToken}`, {expires: new Date(Date.now() + 3600000)});
            req.app.locals.accessToken = newAccessToken;
            // console.log('AccessToken 만료, 재발급 종료');
        }
        res.locals.user = {userId:userId};
        next();
    } catch (error) {
        return res.status(403).send({
            errorMessage: '토큰 인증에 실패했습니다.',
        });
    }
}