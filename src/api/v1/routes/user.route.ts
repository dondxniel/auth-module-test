/* eslint-disable lines-between-class-members */
import { Router } from 'express';
import { validator } from '@middlewares/validator';
import UserControllers from '@controllers/User.controllers';
import userDto from '@dtos/user.dto';

class UserRoute {
  private router;
  private controller = new UserControllers();
  private validator = validator;
  private dto = userDto;
  constructor() {
    this.router = Router();
  }
  initRoutes() {
    this.router.route('/').post(this.validator(this.dto.create), this.controller.create).get(this.controller.get);
    this.router
      .route('/:userId')
      .get(this.validator(this.dto.id), this.controller.getOne)
      .put(this.validator(this.dto.id), this.controller.update)
      .delete(this.validator(this.dto.id), this.controller.delete);
    return this.router;
  }
}

export default new UserRoute();
