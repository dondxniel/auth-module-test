/* eslint-disable lines-between-class-members */
import AuthController from '@controllers/Auth.controllers';
import userDto from '@dtos/user.dto';
import { validator } from '@middlewares/validator';
import { Router } from 'express';

class AuthRoute {
  private router;
  private controller = new AuthController();
  private validator = validator;
  private dto = userDto;
  constructor() {
    this.router = Router();
  }
  initRoutes() {
    this.router.route('/signup').post(this.validator(this.dto.create), this.controller.signup);
    this.router.route('/signin').post(this.validator(this.dto.login), this.controller.login);
    return this.router;
  }
}

export default new AuthRoute();
